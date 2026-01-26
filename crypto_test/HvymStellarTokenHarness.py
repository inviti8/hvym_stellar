from stellar_sdk import Keypair
from hvym_stellar import (
    Stellar25519KeyPair,
    StellarSharedKeyTokenBuilder,
    StellarSharedKeyTokenVerifier,
    TokenType,
)
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


class HvymStellarTokenHarness:

    def __init__(self):
        self.sender = Stellar25519KeyPair(Keypair.random())
        self.receiver = Stellar25519KeyPair(Keypair.random())

    # --------------------------------------------------
    # 1. ACCESS token validation tests
    # --------------------------------------------------
    def test_access_token_valid(self) -> CryptoTestResult:
        caveats = {"role": "user"}
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats=caveats,
            expires_in=300,  # 5 minutes
        )
        token = builder.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=token,
            token_type=TokenType.ACCESS,
            caveats=caveats,
            max_age_seconds=600,
        )

        if not verifier.valid():
            return CryptoTestResult(
                "ACCESS token valid",
                False,
                "CRITICAL",
                "Fresh ACCESS token with correct caveats was rejected",
            )

        return CryptoTestResult(
            "ACCESS token valid",
            True,
            "INFO",
            "Fresh ACCESS token with matching caveats is accepted",
        )

    def test_access_token_wrong_caveat(self) -> CryptoTestResult:
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            expires_in=300,
        )
        token = builder.serialize()

        # Require a different caveat at verification time
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=token,
            token_type=TokenType.ACCESS,
            caveats={"role": "admin"},
            max_age_seconds=600,
        )

        if verifier.valid():
            return CryptoTestResult(
                "ACCESS token wrong caveat",
                False,
                "CRITICAL",
                "Token with mismatched caveats was accepted",
            )

        return CryptoTestResult(
            "ACCESS token wrong caveat",
            True,
            "INFO",
            "Token with mismatched caveats is correctly rejected",
        )

    def test_access_token_wrong_receiver(self) -> CryptoTestResult:
        other_receiver = Stellar25519KeyPair(Keypair.random())

        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            expires_in=300,
        )
        token = builder.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=other_receiver,
            serializedToken=token,
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            max_age_seconds=600,
        )

        if verifier.valid():
            return CryptoTestResult(
                "ACCESS token wrong receiver",
                False,
                "CRITICAL",
                "Token verified successfully with the wrong receiver keypair",
            )

        return CryptoTestResult(
            "ACCESS token wrong receiver",
            True,
            "INFO",
            "Token cannot be verified by an unrelated receiver",
        )

    def test_access_token_expired(self) -> CryptoTestResult:
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={},
            expires_in=1,  # 1 second
        )
        token = builder.serialize()

        # Simulate strict age requirement
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=token,
            token_type=TokenType.ACCESS,
            caveats={},
            max_age_seconds=0,  # effectively "must be fresh"
        )

        # Even if timing is tight, we *expect* this to often fail
        if verifier.valid():
            return CryptoTestResult(
                "ACCESS token expired",
                False,
                "WARNING",
                "Token considered valid under strict max_age_seconds=0",
            )

        return CryptoTestResult(
            "ACCESS token expired",
            True,
            "INFO",
            "Token rejected under strict max_age policy (expiry behavior present)",
        )

    # --------------------------------------------------
    # 2. SECRET token tests
    # --------------------------------------------------
    def test_secret_token_roundtrip(self) -> CryptoTestResult:
        secret_value = "super-secret-value"
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.SECRET,
            caveats={"scope": "test"},
            secret=secret_value,
            expires_in=300,
        )
        token = builder.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=token,
            token_type=TokenType.SECRET,
            caveats={"scope": "test"},
            max_age_seconds=600,
        )

        if not verifier.valid():
            return CryptoTestResult(
                "SECRET token valid",
                False,
                "CRITICAL",
                "SECRET token failed verification before secret extraction",
            )

        try:
            recovered = verifier.secret()
        except Exception as e:
            return CryptoTestResult(
                "SECRET token roundtrip",
                False,
                "CRITICAL",
                f"Failed to recover secret from valid token: {e}",
            )

        if recovered != secret_value:
            return CryptoTestResult(
                "SECRET token roundtrip",
                False,
                "CRITICAL",
                f"Recovered secret mismatch: {recovered!r}",
            )

        return CryptoTestResult(
            "SECRET token roundtrip",
            True,
            "INFO",
            "SECRET token successfully protects and recovers embedded secret",
        )

    def test_secret_token_wrong_receiver(self) -> CryptoTestResult:
        other_receiver = Stellar25519KeyPair(Keypair.random())

        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.SECRET,
            caveats={},
            secret="top-secret",
            expires_in=300,
        )
        token = builder.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=other_receiver,
            serializedToken=token,
            token_type=TokenType.SECRET,
            caveats={},
            max_age_seconds=600,
        )

        try:
            recovered = verifier.secret()
            return CryptoTestResult(
                "SECRET token wrong receiver",
                False,
                "CRITICAL",
                f"Wrong receiver recovered secret: {recovered!r}",
            )
        except Exception:
            return CryptoTestResult(
                "SECRET token wrong receiver",
                True,
                "INFO",
                "Wrong receiver cannot recover embedded secret",
            )

    # --------------------------------------------------
    # 3. Token integrity tests
    # --------------------------------------------------
    def test_token_tampering(self) -> CryptoTestResult:
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={},
            expires_in=300,
        )
        token = builder.serialize()
        token_bytes = bytearray(token.encode("utf-8"))
        token_bytes[-1] ^= 0x01
        tampered = bytes(token_bytes).decode("utf-8", errors="ignore")

        try:
            verifier = StellarSharedKeyTokenVerifier(
                receiverKeyPair=self.receiver,
                serializedToken=tampered,
                token_type=TokenType.ACCESS,
                caveats={},
                max_age_seconds=600,
            )
            valid = verifier.valid()
        except Exception as e:
            # Checksum mismatch or other tampering detected
            valid = False

        if valid:
            return CryptoTestResult(
                "Token tampering",
                False,
                "CRITICAL",
                "Tampered serialized token was accepted as valid"
            )

        return CryptoTestResult(
            "Token tampering",
            True,
            "INFO",
            "Tampered serialized token is rejected"
        )

    def test_token_caveat_escalation(self) -> CryptoTestResult:
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            expires_in=300,
        )
        token = builder.serialize()

        # Naive attacker: try to replace "role = user" with "role = admin" in the serialized form
        tampered = token.replace("role = user", "role = admin")

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=tampered,
            token_type=TokenType.ACCESS,
            caveats={"role": "admin"},
            max_age_seconds=600,
        )

        valid = False
        try:
            valid = verifier.valid()
        except Exception:
            valid = False

        if valid:
            return CryptoTestResult(
                "Caveat escalation",
                False,
                "CRITICAL",
                "Token accepted after caveat escalation (user → admin) without re-signing",
            )

        return CryptoTestResult(
            "Caveat escalation",
            True,
            "INFO",
            "Caveat escalation attempt (user → admin) is rejected",
        )

    def test_token_location_tampering(self) -> CryptoTestResult:
        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={},
            expires_in=300,
        )
        token = builder.serialize()

        # Tamper with the token by flipping a byte in the base64-encoded location
        token_bytes = bytearray(token.encode("utf-8"))
        # Find the end of the location field (it's early in the token)
        # Flip a byte in the middle of the token to corrupt the location
        if len(token_bytes) > 20:
            token_bytes[15] ^= 0x01  # Flip a bit in the encoded location area
        tampered = bytes(token_bytes).decode("utf-8", errors="ignore")

        try:
            verifier = StellarSharedKeyTokenVerifier(
                receiverKeyPair=self.receiver,
                serializedToken=tampered,
                token_type=TokenType.ACCESS,
                caveats={},
                max_age_seconds=600,
            )
            valid = verifier.valid()
        except Exception as e:
            # Checksum mismatch or other tampering detected
            valid = False

        if valid:
            return CryptoTestResult(
                "Location tampering",
                False,
                "CRITICAL",
                "Token accepted after location field tampering",
            )

        return CryptoTestResult(
            "Location tampering",
            True,
            "INFO",
            "Location tampering causes token rejection",
        )

    def test_token_canonical_serialization(self) -> CryptoTestResult:
        from hvym_stellar import (
            StellarSharedKeyTokenBuilder,
            StellarSharedKeyTokenVerifier,
            TokenType,
        )

        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            expires_in=300,
        )
        token1 = builder.serialize()

        # Verify and then re-serialize via a new builder/verifier pair
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=self.receiver,
            serializedToken=token1,
            token_type=TokenType.ACCESS,
            caveats={"role": "user"},
            max_age_seconds=600,
        )

        if not verifier.valid():
            return CryptoTestResult(
                "Token canonical serialization",
                False,
                "CRITICAL",
                "Token failed verification before canonical check",
            )

        # Re-serialize the underlying macaroon and recompute checksum
        inner = verifier._token.serialize()
        import hashlib
        checksum = hashlib.sha256(inner.encode("utf-8")).hexdigest()[:8]
        token2 = inner + "|" + checksum

        if token1 != token2:
            return CryptoTestResult(
                "Token canonical serialization",
                False,
                "WARNING",
                "Token serialization is not canonical (re-serialization differs)",
            )

        return CryptoTestResult(
            "Token canonical serialization",
            True,
            "INFO",
            "Token serialization is canonical under current format",
        )

    def test_token_checksum_tampering(self) -> CryptoTestResult:
        from hvym_stellar import (
            StellarSharedKeyTokenBuilder,
            StellarSharedKeyTokenVerifier,
            TokenType,
        )

        builder = StellarSharedKeyTokenBuilder(
            senderKeyPair=self.sender,
            receiverPub=self.receiver.public_key(),
            token_type=TokenType.ACCESS,
            caveats={},
            expires_in=300,
        )
        token = builder.serialize()

        # Flip last byte of the full token (checksum included)
        tampered_bytes = bytearray(token.encode("utf-8"))
        tampered_bytes[-1] ^= 0x01
        tampered = tampered_bytes.decode("utf-8", errors="ignore")

        try:
            StellarSharedKeyTokenVerifier(
                receiverKeyPair=self.receiver,
                serializedToken=tampered,
                token_type=TokenType.ACCESS,
                caveats={},
                max_age_seconds=600,
            )
            return CryptoTestResult(
                "Token checksum tampering",
                False,
                "CRITICAL",
                "Tampered token passed checksum parsing without error",
            )
        except Exception:
            return CryptoTestResult(
                "Token checksum tampering",
                True,
                "INFO",
                "Tampered token rejected at checksum verification stage",
            )
