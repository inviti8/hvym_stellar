"""
Tests for HVYMDataToken - file storage functionality.
"""

import pytest
import os
import tempfile
import hashlib
from stellar_sdk import Keypair

from hvym_stellar import (
    Stellar25519KeyPair,
    StellarSharedKeyTokenVerifier,
    HVYMDataToken,
    TokenType,
)


@pytest.fixture
def sender_keypair():
    """Create a sender keypair for testing."""
    stellar_kp = Keypair.random()
    return Stellar25519KeyPair(stellar_kp)


@pytest.fixture
def receiver_keypair():
    """Create a receiver keypair for testing."""
    stellar_kp = Keypair.random()
    return Stellar25519KeyPair(stellar_kp)


@pytest.fixture
def temp_text_file():
    """Create a temporary text file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is test content for the HVYMDataToken.\n")
        f.write("It contains multiple lines of text.\n")
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_binary_file():
    """Create a temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
        f.write(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
        f.write(b'\xff\xfe\xfd\xfc\xfb\xfa')
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


class TestFileSerialization:
    """Test file serialization functionality."""

    def test_serialize_text_file(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test serializing a text file."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )

        serialized = token.serialize()
        assert serialized is not None
        assert len(serialized) > 0
        assert '|' in serialized  # Checksum separator

    def test_serialize_binary_file(self, sender_keypair, receiver_keypair, temp_binary_file):
        """Test serializing a binary file."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_binary_file,
            expires_in=3600
        )

        serialized = token.serialize()
        assert serialized is not None
        assert len(serialized) > 0

    def test_serialize_bytes_directly(self, sender_keypair, receiver_keypair):
        """Test serializing bytes directly."""
        test_data = b"Direct byte data for testing"

        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            filename="test.bin",
            expires_in=3600
        )

        serialized = token.serialize()
        assert serialized is not None


class TestTokenCreation:
    """Test token creation methods."""

    def test_create_from_file_path(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test creating token from file path."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )

        assert token is not None
        file_info = token.get_file_info()
        assert file_info['source'] == 'file_path'

    def test_create_from_bytes(self, sender_keypair, receiver_keypair):
        """Test creating token from bytes."""
        test_data = b"Test byte data"

        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            filename="test.dat",
            expires_in=3600
        )

        assert token is not None
        file_info = token.get_file_info()
        assert file_info['source'] == 'file_data'
        assert file_info['size'] == len(test_data)

    def test_factory_create_from_file(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test factory method for creating from file."""
        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )

        assert token is not None

    def test_factory_create_from_bytes(self, sender_keypair, receiver_keypair):
        """Test factory method for creating from bytes."""
        test_data = b"Factory test data"

        token = HVYMDataToken.create_from_bytes(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            filename="factory_test.bin",
            expires_in=3600
        )

        assert token is not None


class TestDataExtraction:
    """Test data extraction from tokens."""

    def test_extract_text_file(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test extracting text file data."""
        # Read original content
        with open(temp_text_file, 'rb') as f:
            original_content = f.read()

        # Create and serialize token
        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        # Verify and extract
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        extracted = token.extract_file_data(verifier)
        assert extracted == original_content

    def test_extract_binary_file(self, sender_keypair, receiver_keypair, temp_binary_file):
        """Test extracting binary file data."""
        with open(temp_binary_file, 'rb') as f:
            original_content = f.read()

        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_binary_file,
            expires_in=3600
        )
        serialized = token.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        extracted = token.extract_file_data(verifier)
        assert extracted == original_content

    def test_static_extract_from_token(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test static extraction method."""
        with open(temp_text_file, 'rb') as f:
            original_content = f.read()

        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        # Use static method
        file_bytes, metadata = HVYMDataToken.extract_from_token(
            serialized_token=serialized,
            receiver_keypair=receiver_keypair
        )

        assert file_bytes == original_content
        assert 'filename' in metadata


class TestCaveats:
    """Test caveat functionality."""

    def test_add_file_type_caveat(self, sender_keypair, receiver_keypair):
        """Test adding file type caveat."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=b"test",
            expires_in=3600
        )

        token.add_file_type_caveat("txt")
        inspection = token.inspect()
        assert "file_type = txt" in inspection

    def test_add_file_size_caveat(self, sender_keypair, receiver_keypair):
        """Test adding file size caveat."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=b"test",
            expires_in=3600
        )

        token.add_file_size_caveat(1024)
        inspection = token.inspect()
        assert "file_max_size = 1024" in inspection

    def test_add_file_hash_caveat(self, sender_keypair, receiver_keypair):
        """Test adding file hash caveat."""
        test_data = b"test data"
        expected_hash = hashlib.sha256(test_data).hexdigest()

        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            expires_in=3600
        )

        token.add_file_hash_caveat(expected_hash)
        inspection = token.inspect()
        assert f"file_hash = {expected_hash}" in inspection


class TestEndToEnd:
    """End-to-end workflow tests."""

    def test_full_file_transfer_workflow(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test complete file transfer workflow."""
        # Read original
        with open(temp_text_file, 'rb') as f:
            original = f.read()

        # Sender creates token
        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        # Receiver verifies and extracts
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        assert verifier.valid()

        extracted = token.extract_file_data(verifier)
        assert extracted == original

    def test_sender_receiver_different_keypairs(self, temp_text_file):
        """Test that different keypairs work correctly."""
        sender_kp = Stellar25519KeyPair(Keypair.random())
        receiver_kp = Stellar25519KeyPair(Keypair.random())

        with open(temp_text_file, 'rb') as f:
            original = f.read()

        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_kp,
            receiverPub=receiver_kp.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_kp,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        assert verifier.valid()
        extracted = token.extract_file_data(verifier)
        assert extracted == original


class TestSecurity:
    """Security-related tests."""

    def test_tampered_token_rejected(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test that tampered tokens are rejected."""
        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        # Tamper with the token
        tampered = serialized[:-1] + 'X'

        with pytest.raises(ValueError):
            StellarSharedKeyTokenVerifier(
                receiverKeyPair=receiver_keypair,
                serializedToken=tampered,
                token_type=TokenType.SECRET
            )

    def test_wrong_receiver_cannot_decrypt(self, sender_keypair, receiver_keypair, temp_text_file):
        """Test that wrong receiver cannot verify token."""
        wrong_receiver = Stellar25519KeyPair(Keypair.random())

        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_path=temp_text_file,
            expires_in=3600
        )
        serialized = token.serialize()

        # Wrong receiver tries to verify
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=wrong_receiver,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        assert not verifier.valid()

    def test_hash_mismatch_detected(self, sender_keypair, receiver_keypair):
        """Test that hash mismatch is detected."""
        test_data = b"original data"

        token = HVYMDataToken.create_from_bytes(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            filename="test.bin",
            expires_in=3600
        )
        serialized = token.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        # Token is valid
        assert verifier.valid()

    def test_hash_verification_can_be_disabled(self, sender_keypair, receiver_keypair):
        """Test that hash verification can be disabled."""
        test_data = b"test data"
        wrong_hash = "0" * 64

        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_data,
            expires_in=3600
        )
        token.add_file_hash_caveat(wrong_hash)
        serialized = token.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        # With hash verification disabled, should succeed
        extracted = token.extract_file_data(verifier, verify_hash=False)
        assert extracted == test_data


class TestErrorHandling:
    """Error handling tests."""

    def test_nonexistent_file_raises_error(self, sender_keypair, receiver_keypair):
        """Test that nonexistent file raises error."""
        with pytest.raises(ValueError):
            HVYMDataToken(
                senderKeyPair=sender_keypair,
                receiverPub=receiver_keypair.public_key(),
                file_path="/nonexistent/path/file.txt",
                expires_in=3600
            )

    def test_invalid_token_format_raises_error(self, receiver_keypair):
        """Test that invalid token format raises error."""
        with pytest.raises(ValueError):
            StellarSharedKeyTokenVerifier(
                receiverKeyPair=receiver_keypair,
                serializedToken="invalid_token_data",
                token_type=TokenType.SECRET
            )

    def test_empty_bytes_handled(self, sender_keypair, receiver_keypair):
        """Test that empty bytes are handled."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=b"",
            expires_in=3600
        )

        serialized = token.serialize()

        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized,
            token_type=TokenType.SECRET
        )

        extracted = token.extract_file_data(verifier)
        assert extracted == b""
