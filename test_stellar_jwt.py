"""
Tests for StellarJWTToken and StellarJWTTokenVerifier

These tests verify the JWT token creation and verification functionality
for tunnel authentication.
"""

import time
import unittest
from stellar_sdk import Keypair
from hvym_stellar import (
    Stellar25519KeyPair,
    StellarJWTToken,
    StellarJWTTokenVerifier,
    StellarJWTSession,
    TokenType,
    DomainSeparation,
)


class TestStellarJWTToken(unittest.TestCase):
    """Tests for JWT token creation."""

    @classmethod
    def setUpClass(cls):
        cls.sender_stellar_kp = Keypair.random()
        cls.receiver_stellar_kp = Keypair.random()

        cls.sender_kp = Stellar25519KeyPair(cls.sender_stellar_kp)
        cls.receiver_kp = Stellar25519KeyPair(cls.receiver_stellar_kp)

        cls.sender_address = cls.sender_stellar_kp.public_key
        cls.receiver_address = cls.receiver_stellar_kp.public_key

    def test_jwt_creation(self):
        """Test basic JWT creation."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            services=["pintheon"],
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # JWT should have 3 parts
        parts = jwt_string.split('.')
        self.assertEqual(len(parts), 3)

    def test_jwt_claims(self):
        """Test JWT claims are correct."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            services=["pintheon", "ipfs"],
            expires_in=3600,
            issuer="custom_issuer",
            claims={"custom_claim": "custom_value"}
        )

        claims = token.get_claims()

        self.assertEqual(claims['sub'], self.sender_address)
        self.assertEqual(claims['aud'], self.receiver_address)
        self.assertEqual(claims['iss'], "custom_issuer")
        self.assertEqual(claims['services'], ["pintheon", "ipfs"])
        self.assertEqual(claims['custom_claim'], "custom_value")
        self.assertIn('iat', claims)
        self.assertIn('exp', claims)

    def test_jwt_default_issuer(self):
        """Test JWT uses default issuer."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address
        )

        claims = token.get_claims()
        self.assertEqual(claims['iss'], "hvym_tunnler")

    def test_jwt_no_expiration(self):
        """Test JWT without expiration."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=None
        )

        claims = token.get_claims()
        self.assertNotIn('exp', claims)

    def test_jwt_inspect(self):
        """Test JWT inspection output."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address
        )

        inspection = token.inspect()
        self.assertIn("JWT Header", inspection)
        self.assertIn("JWT Payload", inspection)
        self.assertIn("EdDSA", inspection)


class TestStellarJWTTokenVerifier(unittest.TestCase):
    """Tests for JWT token verification."""

    @classmethod
    def setUpClass(cls):
        cls.sender_stellar_kp = Keypair.random()
        cls.receiver_stellar_kp = Keypair.random()

        cls.sender_kp = Stellar25519KeyPair(cls.sender_stellar_kp)
        cls.receiver_kp = Stellar25519KeyPair(cls.receiver_stellar_kp)

        cls.sender_address = cls.sender_stellar_kp.public_key
        cls.receiver_address = cls.receiver_stellar_kp.public_key

    def test_jwt_verification_valid(self):
        """Test valid JWT verification."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertTrue(verifier.valid())
        self.assertEqual(verifier.get_stellar_address(), self.sender_address)

    def test_jwt_verification_with_audience(self):
        """Test JWT verification with audience check."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertTrue(verifier.valid(expected_audience=self.receiver_address))

    def test_jwt_verification_wrong_audience(self):
        """Test JWT verification with wrong audience fails."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        wrong_address = Keypair.random().public_key
        self.assertFalse(verifier.valid(expected_audience=wrong_address))

    def test_jwt_verification_with_issuer(self):
        """Test JWT verification with issuer check."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            issuer="custom_issuer"
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertTrue(verifier.valid(expected_issuer="custom_issuer"))
        self.assertFalse(verifier.valid(expected_issuer="wrong_issuer"))

    def test_jwt_expired(self):
        """Test expired JWT rejection."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=-100  # Already expired
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertFalse(verifier.valid())
        self.assertTrue(verifier.is_expired())

    def test_jwt_not_expired(self):
        """Test non-expired JWT."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertFalse(verifier.is_expired())

    def test_jwt_max_age(self):
        """Test JWT max age validation."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # Valid with max age
        verifier = StellarJWTTokenVerifier(jwt_string, max_age_seconds=3600)
        self.assertTrue(verifier.valid())

        # Would fail with very short max age (0 seconds)
        verifier_strict = StellarJWTTokenVerifier(jwt_string, max_age_seconds=-100)
        self.assertFalse(verifier_strict.valid())

    def test_jwt_tampered_signature(self):
        """Test tampered JWT signature rejection."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # Tamper with signature
        parts = jwt_string.split('.')
        tampered = parts[0] + '.' + parts[1] + '.' + parts[2][:-4] + 'XXXX'

        verifier = StellarJWTTokenVerifier(tampered)
        self.assertFalse(verifier.valid())

    def test_jwt_tampered_payload(self):
        """Test tampered JWT payload rejection."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # Tamper with payload (add character)
        parts = jwt_string.split('.')
        tampered = parts[0] + '.X' + parts[1] + '.' + parts[2]

        verifier = StellarJWTTokenVerifier(tampered)
        self.assertFalse(verifier.valid())

    def test_jwt_invalid_format(self):
        """Test invalid JWT format rejection."""
        verifier = StellarJWTTokenVerifier("not.a.valid.jwt.token")
        self.assertFalse(verifier.valid())

        verifier2 = StellarJWTTokenVerifier("invalid")
        self.assertFalse(verifier2.valid())

    def test_jwt_get_services(self):
        """Test getting services from JWT."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            services=["pintheon", "ipfs", "storage"]
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        services = verifier.get_services()
        self.assertEqual(services, ["pintheon", "ipfs", "storage"])

    def test_jwt_verify_returns_claims(self):
        """Test verify() returns claims on success."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            services=["pintheon"]
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        claims = verifier.verify()

        self.assertEqual(claims['sub'], self.sender_address)
        self.assertEqual(claims['aud'], self.receiver_address)

    def test_jwt_verify_raises_on_failure(self):
        """Test verify() raises ValueError on failure."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address,
            expires_in=-100  # Expired
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        with self.assertRaises(ValueError):
            verifier.verify()

    def test_jwt_inspect(self):
        """Test JWT verifier inspection."""
        token = StellarJWTToken(
            keypair=self.sender_kp,
            audience=self.receiver_address
        )
        jwt_string = token.to_jwt()

        verifier = StellarJWTTokenVerifier(jwt_string)
        inspection = verifier.inspect()

        self.assertIn("JWT Header", inspection)
        self.assertIn("JWT Payload", inspection)
        self.assertIn("Signature", inspection)


class TestStellarJWTSession(unittest.TestCase):
    """Tests for JWT session key derivation."""

    @classmethod
    def setUpClass(cls):
        cls.server_stellar_kp = Keypair.random()
        cls.client_stellar_kp = Keypair.random()

        cls.server_kp = Stellar25519KeyPair(cls.server_stellar_kp)
        cls.client_kp = Stellar25519KeyPair(cls.client_stellar_kp)

        cls.server_address = cls.server_stellar_kp.public_key
        cls.client_address = cls.client_stellar_kp.public_key

    def test_session_key_derivation(self):
        """Test session key derivation produces consistent keys."""
        # Server derives key for client
        session = StellarJWTSession(
            server_keypair=self.server_kp,
            client_stellar_address=self.client_address
        )
        server_key = session.derive_shared_key()

        # Key should be 32 bytes
        self.assertEqual(len(server_key), 32)

    def test_session_tunnel_key(self):
        """Test tunnel-specific key derivation."""
        session = StellarJWTSession(
            server_keypair=self.server_kp,
            client_stellar_address=self.client_address
        )

        tunnel_key = session.derive_tunnel_key()
        shared_key = session.derive_shared_key()

        # Tunnel key should use domain separation
        self.assertNotEqual(tunnel_key, shared_key)
        self.assertEqual(len(tunnel_key), 32)

    def test_session_domain_separation(self):
        """Test different domains produce different keys."""
        session = StellarJWTSession(
            server_keypair=self.server_kp,
            client_stellar_address=self.client_address
        )

        key1 = session.derive_shared_key(domain=b"domain1")
        key2 = session.derive_shared_key(domain=b"domain2")

        self.assertNotEqual(key1, key2)


class TestTokenTypeEnum(unittest.TestCase):
    """Test TokenType enum includes TUNNEL."""

    def test_tunnel_token_type_exists(self):
        """Test TUNNEL token type is defined."""
        self.assertEqual(TokenType.TUNNEL.value, 4)
        self.assertEqual(TokenType.ACCESS.value, 1)
        self.assertEqual(TokenType.SECRET.value, 2)


class TestDomainSeparation(unittest.TestCase):
    """Test DomainSeparation includes JWT_SIGNING."""

    def test_jwt_signing_domain_exists(self):
        """Test JWT_SIGNING domain is defined."""
        self.assertIsNotNone(DomainSeparation.JWT_SIGNING)
        self.assertIn(b":jwt:sign", DomainSeparation.JWT_SIGNING)


class TestJWTIntegration(unittest.TestCase):
    """Integration tests for JWT token flow."""

    def test_full_authentication_flow(self):
        """Test complete authentication flow: create, transmit, verify."""
        # Client creates keypair
        client_stellar_kp = Keypair.random()
        client_kp = Stellar25519KeyPair(client_stellar_kp)

        # Server has its own keypair
        server_stellar_kp = Keypair.random()
        server_kp = Stellar25519KeyPair(server_stellar_kp)
        server_address = server_stellar_kp.public_key

        # Client creates JWT
        token = StellarJWTToken(
            keypair=client_kp,
            audience=server_address,
            services=["pintheon"],
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # "Transmit" token to server (just use string)

        # Server verifies token
        verifier = StellarJWTTokenVerifier(jwt_string)
        self.assertTrue(verifier.valid(expected_audience=server_address))

        # Server gets client info
        client_address = verifier.get_stellar_address()
        services = verifier.get_services()

        self.assertEqual(client_address, client_stellar_kp.public_key)
        self.assertEqual(services, ["pintheon"])

        # Server can establish encrypted session
        session = StellarJWTSession(
            server_keypair=server_kp,
            client_stellar_address=client_address
        )
        tunnel_key = session.derive_tunnel_key()
        self.assertEqual(len(tunnel_key), 32)


if __name__ == '__main__':
    unittest.main()
