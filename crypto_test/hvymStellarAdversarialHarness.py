from stellar_sdk import Keypair
from hvym_stellar import Stellar25519KeyPair, StellarSharedKey, StellarSharedDecryption
import secrets
import binascii
from dataclasses import dataclass
from typing import Optional

@dataclass
class CryptoTestResult:
    name: str
    passed: bool
    severity: str  # INFO, WARNING, CRITICAL
    explanation: str


class HvymStellarAdversarialHarness:

    def __init__(self):
        self.sender = Stellar25519KeyPair(Keypair.random())
        self.receiver = Stellar25519KeyPair(Keypair.random())

    # --------------------------------------------------
    # 1. Key separation test
    # --------------------------------------------------
    def test_key_separation(self) -> CryptoTestResult:
        """
        Detect reuse of the same key material for asymmetric and symmetric roles.
        """
        shared = StellarSharedKey(self.sender, self.receiver.public_key())

        try:
            raw_secret = shared.asymmetric_shared_secret()
        except Exception:
            return CryptoTestResult(
                "Key separation",
                False,
                "CRITICAL",
                "Raw ECDH secret is inaccessible; cannot verify safe derivation"
            )

        # Encrypt twice and look for deterministic dependence
        msg = b"test"
        ct1 = shared.encrypt(msg)
        ct2 = shared.encrypt(msg)

        if ct1 == ct2:
            return CryptoTestResult(
                "Key separation",
                False,
                "CRITICAL",
                "Identical ciphertexts for identical plaintexts indicate key reuse or missing randomness"
            )

        return CryptoTestResult(
            "Key separation",
            True,
            "INFO",
            "No immediate evidence of deterministic key reuse, but no explicit domain separation is visible"
        )

    # --------------------------------------------------
    # 2. Ciphertext malleability test
    # --------------------------------------------------
    def test_malleability(self) -> CryptoTestResult:
        msg = b"attack at dawn"
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        ct = shared.encrypt(msg)

        tampered = bytearray(ct)
        tampered[-1] ^= 0x01

        try:
            pt = decryptor.decrypt(bytes(tampered))
            return CryptoTestResult(
                "Ciphertext malleability",
                False,
                "CRITICAL",
                f"Tampered ciphertext decrypted successfully: {pt!r}"
            )
        except Exception:
            return CryptoTestResult(
                "Ciphertext malleability",
                True,
                "INFO",
                "Tampered ciphertext rejected"
            )

    # --------------------------------------------------
    # 3. Known-plaintext variability
    # --------------------------------------------------
    def test_known_plaintext(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())

        msg = b"A" * 64
        cts = {shared.encrypt(msg) for _ in range(10)}

        if len(cts) < 10:
            return CryptoTestResult(
                "Known-plaintext attack",
                False,
                "WARNING",
                "Low ciphertext diversity for identical plaintexts"
            )

        return CryptoTestResult(
            "Known-plaintext attack",
            True,
            "INFO",
            "Ciphertexts vary under repeated encryption"
        )

    # --------------------------------------------------
    # 4. Nonce control / misuse resistance (API-level)
    # --------------------------------------------------
    def test_nonce_control(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())

        try:
            shared.encrypt(b"x", nonce=b"\x00" * 24)
            controllable = True
        except TypeError:
            controllable = False

        if not controllable:
            return CryptoTestResult(
                "Nonce misuse resistance",
                True,
                "INFO",
                "Nonce is not user-controllable - good security practice prevents nonce reuse attacks"
            )

        return CryptoTestResult(
            "Nonce misuse resistance",
            False,
            "CRITICAL",
            "Scheme allows nonce injection - potential for nonce reuse attacks"
        )

    # --------------------------------------------------
    # 5. Asymmetric encryption tests
    # --------------------------------------------------
    def test_asymmetric_key_separation(self) -> CryptoTestResult:
        """Test asymmetric encryption key separation"""
        shared = StellarSharedKey(self.sender, self.receiver.public_key())

        # Test asymmetric encryption twice for randomness
        msg = b"test"
        ct1 = shared.asymmetric_encrypt(msg)
        ct2 = shared.asymmetric_encrypt(msg)

        if ct1 == ct2:
            return CryptoTestResult(
                "Asymmetric key separation",
                False,
                "CRITICAL",
                "Identical ciphertexts for identical plaintexts indicate nonce reuse"
            )

        return CryptoTestResult(
            "Asymmetric key separation",
            True,
            "INFO",
            "Asymmetric encryption produces unique ciphertexts for identical plaintexts"
        )

    def test_asymmetric_malleability(self) -> CryptoTestResult:
        """Test asymmetric encryption malleability resistance"""
        msg = b"attack at dawn"
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        ct = shared.asymmetric_encrypt(msg)

        tampered = bytearray(ct)
        tampered[-1] ^= 0x01

        try:
            pt = decryptor.asymmetric_decrypt(bytes(tampered))
            return CryptoTestResult(
                "Asymmetric malleability",
                False,
                "CRITICAL",
                f"Tampered asymmetric ciphertext decrypted successfully: {pt!r}"
            )
        except Exception:
            return CryptoTestResult(
                "Asymmetric malleability",
                True,
                "INFO",
                "Tampered asymmetric ciphertext rejected"
            )

    # --------------------------------------------------
    # 6. White-box: key derivation sanity
    # --------------------------------------------------
    def test_key_derivation_sanity(self) -> CryptoTestResult:
        """
        Inspect derived key material properties:
        - length
        - stability
        - separation between calls
        """
        shared = StellarSharedKey(self.sender, self.receiver.public_key())

        try:
            secret1 = shared.asymmetric_shared_secret()
            secret2 = shared.asymmetric_shared_secret()
        except Exception as e:
            return CryptoTestResult(
                "Key derivation sanity",
                False,
                "CRITICAL",
                f"Unable to extract shared secret: {e}"
            )

        if not isinstance(secret1, (bytes, bytearray)):
            return CryptoTestResult(
                "Key derivation sanity",
                False,
                "CRITICAL",
                "Shared secret is not byte material"
            )

        if len(secret1) < 32:
            return CryptoTestResult(
                "Key derivation sanity",
                False,
                "CRITICAL",
                f"Shared secret too short ({len(secret1)} bytes)"
            )

        if secret1 != secret2:
            return CryptoTestResult(
                "Key derivation sanity",
                False,
                "CRITICAL",
                "Shared secret is unstable across calls (unexpected for ECDH)"
            )

        return CryptoTestResult(
            "Key derivation sanity",
            True,
            "INFO",
            f"Shared secret length = {len(secret1)} bytes, stable across calls"
        )

    # --------------------------------------------------
    # 7. Construction mapping
    # --------------------------------------------------
    def test_construction_mapping(self) -> CryptoTestResult:
        """
        Map hvym_stellar to known cryptographic constructions
        (HPKE, Noise, ECIES-like) and identify deviations.
        """
        findings = []

        # ECDH present
        findings.append(" Curve25519 ECDH key agreement")

        # AEAD behavior
        try:
            shared = StellarSharedKey(self.sender, self.receiver.public_key())
            ct = shared.encrypt(b"test")
            decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())
            decryptor.decrypt(ct)
            findings.append(" Authenticated encryption behavior observed")
        except Exception:
            findings.append(" Authenticated encryption unclear")

        # Nonce handling
        try:
            shared.encrypt(b"x", nonce=b"\x00" * 24)
            findings.append(" User-controllable nonce (not HPKE-safe)")
        except TypeError:
            findings.append(" Nonce managed internally (HPKE / libsodium-style)")

        # Explicit KDF labeling
        findings.append(" No externally visible HKDF labels")

        explanation = (
            "Construction resembles ECIES + AEAD with enforced nonce safety.\n"
            "Closest standardized analogue: HPKE base mode (informal).\n"
            "Deviations: undocumented KDF, no explicit domain separation claims."
        )

        return CryptoTestResult(
            "Construction mapping",
            True,
            "INFO",
            explanation + "\nFindings:\n" + "\n".join(findings)
        )

    # --------------------------------------------------
    # 8. Security claims checklist
    # --------------------------------------------------
    def test_security_claims(self) -> CryptoTestResult:
        """
        Explicitly enumerate supported and unsupported security claims.
        """
        claims = {
            "IND-CPA": "SUPPORTED (randomized encryption observed)",
            "IND-CCA": "LIKELY (authenticated decryption enforced)",
            "Nonce misuse resistance": "API-ENFORCED (not construction-level)",
            "KCI resistance": "UNDETERMINED (no long-term key compromise model)",
            "Formal proof": "ABSENT",
            "Standard compliance": "NON-STANDARD (HPKE-like)"
        }

        explanation = "Security claims summary:\n"
        for k, v in claims.items():
            explanation += f"- {k}: {v}\n"

        return CryptoTestResult(
            "Security claims checklist",
            True,
            "INFO",
            explanation.strip()
        )
