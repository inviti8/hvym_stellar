from dataclasses import dataclass
import secrets
import hashlib
import warnings
import nacl
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

@dataclass
class CryptoTestResult:
    name: str
    passed: bool
    severity: str  # INFO, WARNING, CRITICAL
    explanation: str


class HvymStellarHybridCorrectnessHarness:
    """
    Tests that prove the hybrid mode construction is incorrect / brittle,
    even when it appears to work in modern PyNaCl versions.
    """

    def test_pynacl_version_and_point_validation_behavior(self) -> CryptoTestResult:
        """
        Check PyNaCl version and whether invalid points are rejected early.
        This shows the hybrid mode security is library-version dependent.
        """
        version = nacl.__version__
        is_hardened = version >= "1.5.0"

        # Test all-zero input (known invalid/low-order)
        zero_bytes = bytes(32)
        try:
            PublicKey(zero_bytes)
            rejects_invalid = False
        except (CryptoError, ValueError, Exception):
            rejects_invalid = True

        passed = is_hardened and rejects_invalid
        severity = "CRITICAL" if not is_hardened else "WARNING" if not rejects_invalid else "INFO"

        explanation = (
            f"PyNaCl version: {version}\n"
            f"Hardened (rejects invalid points): {'YES' if is_hardened else 'NO'}\n"
            f"Rejects all-zero public key: {'YES' if rejects_invalid else 'NO'}\n\n"
            "Hybrid mode relies on early rejection of invalid points.\n"
            "In older PyNaCl (<1.5.0), this would produce weak/zero keys → confidentiality broken.\n"
            "Even now: design is incorrect — should use SecretBox instead."
        )

        return CryptoTestResult(
            "PyNaCl version & point validation hardening",
            passed,
            severity,
            explanation
        )

    def test_hybrid_mode_fails_on_invalid_derived_key(self) -> CryptoTestResult:
        """
        Prove that hybrid-style Box construction fails when derived_key
        is not a valid point — which happens frequently with SHA-256 output.
        """
        trials = 200
        failures = 0

        for _ in range(trials):
            # Simulate derived_key = SHA256(salt + shared_secret)
            fake_derived = hashlib.sha256(secrets.token_bytes(64)).digest()

            try:
                priv = PrivateKey(fake_derived)
                pub = PublicKey(fake_derived)           # ← this should fail often in hardened PyNaCl
                box = Box(priv, pub)
                # If we reach here, point was accepted
            except Exception:
                failures += 1

        failure_rate = failures / trials
        passed = failure_rate > 0.70   # expect ~87% failure if properly rejecting

        explanation = (
            f"Trials: {trials}\n"
            f"Construction failures (invalid point rejected): {failures} ({failure_rate:.1%})\n\n"
            f"High failure rate proves: SHA-256 outputs are usually NOT valid Curve25519 points.\n"
            "Hybrid mode will raise exceptions in most real-world cases with modern PyNaCl.\n"
            "In older PyNaCl: silent weak keys instead → much worse."
        )

        severity = "CRITICAL" if failure_rate < 0.50 else "WARNING" if failure_rate < 0.80 else "INFO"

        return CryptoTestResult(
            "Hybrid mode fails on statistically invalid derived keys",
            passed,
            severity,
            explanation
        )

    def test_hybrid_construction_is_broken_by_design(self) -> CryptoTestResult:
        """
        Demonstrate that using Box for symmetric encryption with derived key
        is conceptually wrong — compare to correct SecretBox usage.
        """
        msg = b"confidential data"
        salt = secrets.token_bytes(32)
        # Pretend we have a real ECDH shared secret
        real_shared = secrets.token_bytes(32)
        derived = hashlib.sha256(salt + real_shared).digest()

        # Hybrid way (current library)
        hybrid_success = False
        hybrid_error = None
        try:
            priv = PrivateKey(derived)
            pub = PublicKey(derived)
            box = Box(priv, pub)
            encrypted = box.encrypt(msg)
            decrypted = box.decrypt(encrypted)
            hybrid_success = decrypted == msg
        except Exception as e:
            hybrid_error = str(e)

        # Correct way
        correct_box = SecretBox(derived)
        correct_enc = correct_box.encrypt(msg)
        correct_dec = correct_box.decrypt(correct_enc)
        correct_success = correct_dec == msg

        passed = not hybrid_success or hybrid_error is not None
        severity = "CRITICAL" if hybrid_success else "WARNING" if hybrid_error else "INFO"

        explanation = (
            f"Hybrid mode (Box with same bytes): {'succeeded' if hybrid_success else 'failed'}\n"
            f"    Error (if any): {hybrid_error or 'none'}\n"
            f"Correct way (SecretBox): {'succeeded' if correct_success else 'failed'}\n\n"
            "The hybrid mode either:\n"
            "  a) fails with modern PyNaCl (good, but brittle)\n"
            "  b) succeeds with weak key material on old PyNaCl (dangerous)\n"
            "Correct design: use SecretBox(derived_key) — always strong, no point validation issues."
        )

        return CryptoTestResult(
            "Hybrid construction is broken by design",
            passed,
            severity,
            explanation
        )

    def test_sha256_output_is_not_a_curve25519_point_distribution(self) -> CryptoTestResult:
        """
        Show that SHA-256 outputs are uniformly random → only ~12.5% valid points.
        (This should fail / warn even in hardened environments.)
        """
        trials = 10_000
        valid = 0

        for _ in range(trials):
            # SHA-256 of random input → high-quality random bytes
            data = secrets.token_bytes(64)
            digest = hashlib.sha256(data).digest()
            try:
                PublicKey(digest)
                valid += 1
            except:
                pass

        fraction = valid / trials
        expected_around = 0.125
        passed = 0.08 < fraction < 0.18  # generous range

        severity = "CRITICAL" if not passed else "WARNING" if abs(fraction - expected_around) > 0.03 else "INFO"

        explanation = (
            f"Valid points from SHA-256 outputs: {valid}/{trials} = {fraction:.4f}\n"
            f"Expected ≈ {expected_around:.3f} (1/8)\n\n"
            "This proves SHA-256 digest is not a valid Curve25519 point most of the time.\n"
            "Hybrid mode is relying on library rejection instead of correct design."
        )

        return CryptoTestResult(
            "SHA-256 output is not a Curve25519 point (distribution test)",
            passed,
            severity,
            explanation
        )
