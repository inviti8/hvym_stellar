from dataclasses import dataclass
from typing import Optional
import secrets
import binascii
import hashlib
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError

@dataclass
class CryptoTestResult:
    name: str
    passed: bool
    severity: str  # INFO, WARNING, CRITICAL
    explanation: str


class HvymStellarHybridDangerHarness:
    """
    Tests specifically targeting the dangerous construction in hybrid mode:
    Box(PrivateKey(derived_key), PublicKey(derived_key)) with same bytes.
    """
    
    def __init__(self):
        # We don't need real keypairs for these — we're simulating the derived_key path
        pass

    # --------------------------------------------------------------------------
    # 1. Fraction of valid Curve25519 public keys from random 32-byte values
    # --------------------------------------------------------------------------
    def test_derived_key_valid_point_probability(self) -> CryptoTestResult:
        """
        Statistically verify how often a random 32-byte value (like SHA-256 output)
        is accepted as a valid Curve25519 public key.
        """
        trials = 100_000
        valid_count = 0
        
        for _ in range(trials):
            candidate = secrets.token_bytes(32)
            try:
                PublicKey(candidate)
                valid_count += 1
            except:
                pass
        
        fraction = valid_count / trials
        passed = fraction > 0.10  # We expect ~0.125, but anything suspiciously low fails
        
        explanation = (
            f"Valid Curve25519 points: {valid_count}/{trials} = {fraction:.4f}\n"
            "Expected ≈0.125 (1/8). Significantly lower values indicate broken point validation."
        )
        
        severity = "CRITICAL" if fraction < 0.05 else "WARNING" if fraction < 0.10 else "INFO"
        
        return CryptoTestResult(
            "Derived key valid point probability",
            passed,
            severity,
            explanation
        )

    # --------------------------------------------------------------------------
    # 2. Frequency of zero / near-zero shared secrets in hybrid construction
    # --------------------------------------------------------------------------
    def test_hybrid_shared_secret_entropy_collapse(self) -> CryptoTestResult:
        """
        Count how often the hybrid Box construction produces a zero or very low-entropy
        shared secret (classic symptom of invalid point multiplication).
        """
        trials = 500
        zero_count = 0
        low_entropy_count = 0
        
        for _ in range(trials):
            # Simulate derived_key = SHA256(salt + real_shared) — use random bytes
            derived = secrets.token_bytes(32)
            try:
                priv = PrivateKey(derived)
                pub = PublicKey(derived)  # ← the dangerous line
                box = Box(priv, pub)
                shared = box.shared_key()
                
                if all(b == 0 for b in shared):
                    zero_count += 1
                elif sum(1 for b in shared if b in (0, 255)) > 20:  # very biased bytes
                    low_entropy_count += 1
                    
            except CryptoError:
                # Rare — point decoding failed hard
                low_entropy_count += 1
        
        bad_rate = (zero_count + low_entropy_count) / trials
        passed = bad_rate < 0.01  # We expect significant fraction to be bad
        
        explanation = (
            f"Trials: {trials}\n"
            f"Zero shared secrets: {zero_count}\n"
            f"Very low-entropy shared secrets: {low_entropy_count}\n"
            f"Bad rate: {bad_rate:.3f} ({bad_rate*100:.1f}%)\n"
            "High bad rate → effective encryption key is predictable or zero → confidentiality broken."
        )
        
        severity = "CRITICAL" if bad_rate > 0.10 else "WARNING" if bad_rate > 0.01 else "INFO"
        
        return CryptoTestResult(
            "Hybrid shared secret entropy collapse",
            passed,
            severity,
            explanation
        )

    # --------------------------------------------------------------------------
    # 3. Round-trip succeeds even when shared secret is all zeros
    # --------------------------------------------------------------------------
    def test_hybrid_roundtrip_with_zero_shared_secret(self) -> CryptoTestResult:
        """
        Demonstrate that encryption/decryption "succeeds" even when the derived
        shared secret is cryptographically worthless (all zeros).
        """
        msg = b"this should be secret but isn't"
        
        # Force zero shared secret scenario
        zero_bytes = bytes(32)
        try:
            priv = PrivateKey(zero_bytes)
            pub = PublicKey(zero_bytes)
            box = Box(priv, pub)
            
            encrypted = box.encrypt(msg)
            decrypted = box.decrypt(encrypted)
            
            success = decrypted == msg
            explanation = (
                "Round-trip succeeded with all-zero shared secret.\n"
                "This proves: functionality passes even when key material is completely broken.\n"
                "Attackers who can force/guess invalid points can trivially decrypt."
            )
            severity = "CRITICAL"
            passed = False  # This should NEVER be acceptable
            
        except Exception as e:
            success = False
            explanation = f"Failed (unexpected): {str(e)}"
            severity = "WARNING"
            passed = True  # Rare failure might indicate libsodium changed behavior
        
        return CryptoTestResult(
            "Hybrid round-trip with zero shared secret",
            passed,
            severity,
            explanation + f"\nSuccess: {success}"
        )

    # --------------------------------------------------------------------------
    # 4. Compare hybrid Box vs proper SecretBox (recommended fix)
    # --------------------------------------------------------------------------
    def test_hybrid_vs_proper_symmetric_key_strength(self) -> CryptoTestResult:
        """
        Compare entropy / uniformity of shared key from hybrid Box vs what
        SecretBox would use (correct way to derive symmetric key).
        """
        trials = 100
        hybrid_zero_rate = 0
        # We can't easily measure full entropy, so we check for zero-key frequency
        
        for _ in range(trials):
            derived = secrets.token_bytes(32)  # simulate SHA-256 output
            try:
                priv = PrivateKey(derived)
                pub = PublicKey(derived)
                box = Box(priv, pub)
                shared = box.shared_key()
                if all(b == 0 for b in shared):
                    hybrid_zero_rate += 1
            except:
                hybrid_zero_rate += 1  # Treat failure as bad
        
        hybrid_zero_rate /= trials
        
        explanation = (
            f"Hybrid Box zero-key rate: {hybrid_zero_rate:.3f} ({hybrid_zero_rate*100:.1f}%)\n"
            "Proper SecretBox(derived) would always use full 256-bit key — zero rate = 0.0\n"
            "Recommendation: switch hybrid mode to nacl.secret.SecretBox(derived_key)"
        )
        
        passed = hybrid_zero_rate < 0.001
        severity = "CRITICAL" if hybrid_zero_rate > 0.05 else "WARNING"
        
        return CryptoTestResult(
            "Hybrid vs proper symmetric key strength",
            passed,
            severity,
            explanation
        )
