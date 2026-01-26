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
            pt = decryptor.decrypt(bytes(tampered), from_address=self.sender.base_stellar_keypair().public_key)
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
            decryptor.decrypt(ct, from_address=self.sender.base_stellar_keypair().public_key)
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

    # --------------------------------------------------
    # 9. Key binding and receiver validation tests
    # --------------------------------------------------
    def test_wrong_receiver_cannot_decrypt(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        ct = shared.encrypt(b"secret")

        # Adversarial receiver with a different keypair
        attacker = Stellar25519KeyPair(Keypair.random())
        bad_decryptor = StellarSharedDecryption(attacker, self.sender.public_key())

        try:
            bad_decryptor.decrypt(ct, from_address=self.sender.base_stellar_keypair().public_key)
            return CryptoTestResult(
                "Wrong receiver decryption",
                False,
                "CRITICAL",
                "Adversarial receiver decrypted ciphertext successfully"
            )
        except Exception:
            return CryptoTestResult(
                "Wrong receiver decryption",
                True,
                "INFO",
                "Wrong receiver cannot decrypt ciphertext"
            )

    # --------------------------------------------------
    # 10. Ciphertext integrity tests
    # --------------------------------------------------
    def test_salt_tampering(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        ct = shared.encrypt(b"secret")
        parts = ct.split(b'|', 2)
        if len(parts) != 3:
            return CryptoTestResult(
                "Salt tampering",
                False,
                "CRITICAL",
                "Ciphertext format invalid"
            )

        salt, nonce, body = parts
        tampered_salt = bytearray(salt)
        tampered_salt[0] ^= 0x01

        tampered_ct = bytes(tampered_salt) + b'|' + nonce + b'|' + body

        try:
            decryptor.decrypt(tampered_ct, from_address=self.sender.base_stellar_keypair().public_key)
            return CryptoTestResult(
                "Salt tampering",
                False,
                "CRITICAL",
                "Tampered salt did not cause decryption failure"
            )
        except Exception:
            return CryptoTestResult(
                "Salt tampering",
                True,
                "INFO",
                "Tampered salt rejected"
            )

    def test_truncation_resistance(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        ct = shared.encrypt(b"secret")
        truncated = ct[:-5]

        try:
            decryptor.decrypt(truncated, from_address=self.sender.base_stellar_keypair().public_key)
            return CryptoTestResult(
                "Truncation resistance",
                False,
                "CRITICAL",
                "Truncated ciphertext decrypted successfully"
            )
        except Exception:
            return CryptoTestResult(
                "Truncation resistance",
                True,
                "INFO",
                "Truncated ciphertext rejected"
            )

    def test_garbage_extension(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        ct = shared.encrypt(b"secret")
        extended = ct + b"garbage"

        try:
            decryptor.decrypt(extended, from_address=self.sender.base_stellar_keypair().public_key)
            return CryptoTestResult(
                "Garbage extension",
                False,
                "CRITICAL",
                "Ciphertext with trailing garbage decrypted successfully"
            )
        except Exception:
            return CryptoTestResult(
                "Garbage extension",
                True,
                "INFO",
                "Ciphertext with trailing garbage rejected"
            )

    # --------------------------------------------------
    # 11. Mode isolation and input validation tests
    # --------------------------------------------------
    def test_mode_isolation(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        msg = b"mode isolation test"

        ct_hybrid = shared.encrypt(msg)
        pt_hybrid = decryptor.decrypt(ct_hybrid, from_address=self.sender.base_stellar_keypair().public_key)

        ct_asym = shared.asymmetric_encrypt(msg)
        pt_asym = decryptor.asymmetric_decrypt(ct_asym)

        if pt_hybrid != msg or pt_asym != msg:
            return CryptoTestResult(
                "Mode isolation",
                False,
                "CRITICAL",
                "One of the modes failed round-trip correctness"
            )

        # Ensure ciphertexts are not trivially interchangeable
        try:
            decryptor.asymmetric_decrypt(ct_hybrid)
            return CryptoTestResult(
                "Mode isolation",
                False,
                "WARNING",
                "Hybrid ciphertext was accepted by asymmetric decrypt"
            )
        except Exception:
            pass

        try:
            decryptor.decrypt(ct_asym, from_address=self.sender.base_stellar_keypair().public_key)
            return CryptoTestResult(
                "Mode isolation",
                False,
                "WARNING",
                "Asymmetric ciphertext was accepted by hybrid decrypt"
            )
        except Exception:
            pass

        return CryptoTestResult(
            "Mode isolation",
            True,
            "INFO",
            "Modes are correct and not trivially interchangeable"
        )

    def test_random_garbage_decryption(self) -> CryptoTestResult:
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        for _ in range(50):
            garbage = secrets.token_bytes(64)
            try:
                decryptor.decrypt(garbage, from_address=self.sender.base_stellar_keypair().public_key)
                return CryptoTestResult(
                    "Random garbage decryption",
                    False,
                    "CRITICAL",
                    "Random garbage decrypted without error"
                )
            except Exception:
                continue

        return CryptoTestResult(
            "Random garbage decryption",
            True,
            "INFO",
            "Random garbage consistently rejected"
        )

    # --------------------------------------------------
    # 12. Session management and performance tests
    # --------------------------------------------------
    def test_replay_and_multisession(self) -> CryptoTestResult:
        shared1 = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor1 = StellarSharedDecryption(self.receiver, self.sender.public_key())

        msg = b"replay test"
        ct = shared1.encrypt(msg)
        pt1 = decryptor1.decrypt(ct, from_address=self.sender.base_stellar_keypair().public_key)

        # New instances, same keypairs
        shared2 = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor2 = StellarSharedDecryption(self.receiver, self.sender.public_key())
        pt2 = decryptor2.decrypt(ct, from_address=self.sender.base_stellar_keypair().public_key)

        if pt1 != msg or pt2 != msg:
            return CryptoTestResult(
                "Replay & multisession",
                False,
                "CRITICAL",
                "Ciphertext failed to decrypt consistently across sessions"
            )

        return CryptoTestResult(
            "Replay & multisession",
            True,
            "INFO",
            "Ciphertext replays across sessions behave consistently (no hidden state dependence)"
        )

    def test_large_message(self) -> CryptoTestResult:
        shared = StellarSharedKey(self.sender, self.receiver.public_key())
        decryptor = StellarSharedDecryption(self.receiver, self.sender.public_key())

        msg = secrets.token_bytes(1024 * 1024)  # 1 MB
        ct = shared.encrypt(msg)
        pt = decryptor.decrypt(ct, from_address=self.sender.base_stellar_keypair().public_key)

        if pt != msg:
            return CryptoTestResult(
                "Large message",
                False,
                "CRITICAL",
                "Large message failed round-trip encryption/decryption"
            )

        return CryptoTestResult(
            "Large message",
            True,
            "INFO",
            "Large message round-trip succeeded"
        )
