"""
Tests for HVYM Data Token File Format enhancements.

Tests the new .hvym file format with magic bytes, headers, and convenience methods.
"""

import pytest
import os
import tempfile
import struct
import json
from datetime import datetime, timezone

from hvym_stellar import (
    Stellar25519KeyPair,
    HVYMDataToken,
)
from stellar_sdk import Keypair


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
def test_file_data():
    """Create test file data."""
    return b"This is test file content for HVYM format testing.\n" * 10


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


class TestHVYMFileFormat:
    """Test HVYM file format with magic bytes and headers."""

    def test_hvym_constants(self):
        """Test HVYM format constants are properly defined."""
        assert HVYMDataToken.HVYM_EXTENSION == '.hvym'
        assert HVYMDataToken.HVYM_MAGIC_BYTES == b'HVYMTOKN'
        assert HVYMDataToken.HVYM_FORMAT_VERSION == (1, 0)
        assert HVYMDataToken.LEGACY_FORMAT_SUPPORT is True

    def test_to_hvym_file_creates_proper_format(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test that to_hvym_file creates proper binary format."""
        # Create token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="test.txt",
            expires_in=3600
        )

        # Save as HVYM file
        hvym_path = os.path.join(temp_dir, "test_token")
        saved_path = token.to_hvym_file(hvym_path)

        # Verify path has .hvym extension
        assert saved_path.endswith('.hvym')
        assert os.path.exists(saved_path)

        # Verify binary format structure
        with open(saved_path, 'rb') as f:
            # Check magic bytes
            magic = f.read(8)
            assert magic == HVYMDataToken.HVYM_MAGIC_BYTES

            # Check version
            version_major = struct.unpack('<H', f.read(2))[0]
            version_minor = struct.unpack('<H', f.read(2))[0]
            assert version_major == 1
            assert version_minor == 0

            # Check flags (should be 0)
            flags = struct.unpack('<H', f.read(2))[0]
            assert flags == 0

            # Check header length
            header_length = struct.unpack('<I', f.read(4))[0]
            assert header_length > 0

            # Read and validate JSON header
            json_header = f.read(header_length).decode('utf-8')
            header_data = json.loads(json_header)
            
            required_fields = ['version', 'created_at', 'original_filename', 'file_size', 'file_hash', 'token_type']
            for field in required_fields:
                assert field in header_data

            assert header_data['version'] == '1.0'
            assert header_data['original_filename'] == 'test.txt'
            assert header_data['file_size'] == len(test_file_data)
            assert header_data['token_type'] == 'biscuit'

            # Verify token data follows header
            token_data = f.read().decode('utf-8')
            assert len(token_data) > 0
            assert HVYMDataToken.BISCUIT_DELIMITER in token_data

    def test_auto_extension_behavior(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test auto-extension behavior."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="test.txt"
        )

        # Test with auto_extension=True (default)
        path1 = token.to_hvym_file(os.path.join(temp_dir, "test1"))
        assert path1.endswith('.hvym')
        assert os.path.exists(path1)

        # Test with auto_extension=False
        path2 = token.to_hvym_file(os.path.join(temp_dir, "test2.hvym"), auto_extension=False)
        assert path2.endswith('.hvym')
        assert os.path.exists(path2)

        # Test with existing extension
        path3 = token.to_hvym_file(os.path.join(temp_dir, "test3.hvym"))
        assert path3.endswith('.hvym')
        assert path3 == os.path.join(temp_dir, "test3.hvym")

    def test_from_hvym_file_loads_properly(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test that from_hvym_file loads and decrypts properly."""
        # Create and save token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="test.txt",
            expires_in=3600
        )

        hvym_path = os.path.join(temp_dir, "test_token.hvym")
        token.to_hvym_file(hvym_path)

        # Load and decrypt
        file_bytes, metadata = HVYMDataToken.from_hvym_file(hvym_path, receiver_keypair)

        # Verify extracted data
        assert file_bytes == test_file_data
        assert metadata['filename'] == 'test.txt'
        assert metadata['original_filename'] == 'test.txt'
        assert metadata['file_size'] == len(test_file_data)
        assert metadata['token_type'] == 'biscuit'
        assert metadata['version'] == '1.0'
        assert 'created_at' in metadata

    def test_extract_to_file_convenience(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test extract_to_file convenience method."""
        # Create and save token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="extracted_test.txt"
        )

        hvym_path = os.path.join(temp_dir, "source_token.hvym")
        token.to_hvym_file(hvym_path)

        # Extract to file
        extracted_path = HVYMDataToken.extract_to_file(hvym_path, receiver_keypair)

        # Verify extracted file
        assert os.path.exists(extracted_path)
        assert extracted_path.endswith('extracted_test.txt')

        with open(extracted_path, 'rb') as f:
            extracted_data = f.read()
        assert extracted_data == test_file_data

    def test_extract_to_file_custom_output(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test extract_to_file with custom output directory and filename."""
        # Create and save token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="original.txt"
        )

        hvym_path = os.path.join(temp_dir, "source_token.hvym")
        token.to_hvym_file(hvym_path)

        # Extract with custom parameters
        output_dir = os.path.join(temp_dir, "custom_output")
        extracted_path = HVYMDataToken.extract_to_file(
            hvym_path, 
            receiver_keypair,
            output_dir=output_dir,
            output_filename="custom_name.txt"
        )

        # Verify extracted file
        assert os.path.exists(extracted_path)
        assert extracted_path == os.path.join(output_dir, "custom_name.txt")

        with open(extracted_path, 'rb') as f:
            extracted_data = f.read()
        assert extracted_data == test_file_data

    def test_validate_hvym_file_valid(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test validate_hvym_file with valid files."""
        # Create and save token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="validate_test.txt"
        )

        hvym_path = os.path.join(temp_dir, "valid_token.hvym")
        token.to_hvym_file(hvym_path)

        # Validate file
        result = HVYMDataToken.validate_hvym_file(hvym_path)

        assert result['valid'] is True
        assert result['format'] == 'hvym'
        assert result['version'] == '1.0'
        assert result['original_filename'] == 'validate_test.txt'
        assert result['file_size'] == len(test_file_data)
        assert result['token_type'] == 'biscuit'
        assert 'created_at' in result
        assert 'file_hash' in result

    def test_validate_hvym_file_nonexistent(self):
        """Test validate_hvym_file with nonexistent file."""
        with pytest.raises(ValueError, match="File not found"):
            HVYMDataToken.validate_hvym_file("/nonexistent/path/file.hvym")

    def test_is_hvym_format_detection(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test _is_hvym_format helper method."""
        # Create HVYM file
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="test.txt"
        )

        hvym_path = os.path.join(temp_dir, "test.hvym")
        token.to_hvym_file(hvym_path)

        # Test detection
        assert HVYMDataToken._is_hvym_format(hvym_path) is True

        # Create non-HVYM file
        regular_path = os.path.join(temp_dir, "regular.txt")
        with open(regular_path, 'w') as f:
            f.write("This is not an HVYM file")

        assert HVYMDataToken._is_hvym_format(regular_path) is False

    def test_backward_compatibility_legacy_format(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test backward compatibility with legacy token files."""
        # Create token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="legacy_test.txt"
        )

        # Save in legacy format (plain text)
        legacy_path = os.path.join(temp_dir, "legacy_token.txt")
        token.save_token_to_file(legacy_path)

        # Load using new from_hvym_file method
        file_bytes, metadata = HVYMDataToken.from_hvym_file(legacy_path, receiver_keypair)

        assert file_bytes == test_file_data
        assert metadata['format'] == 'legacy'

    def test_invalid_hvym_format_detection(self, temp_dir):
        """Test detection of invalid HVYM files."""
        # Create file with wrong magic bytes
        invalid_path = os.path.join(temp_dir, "invalid.hvym")
        with open(invalid_path, 'wb') as f:
            f.write(b'WRONGMAG')  # Wrong magic bytes
            f.write(b'\x00' * 10)  # Some padding

        # Should not be detected as HVYM format
        assert HVYMDataToken._is_hvym_format(invalid_path) is False

        # Validation should fail gracefully
        result = HVYMDataToken.validate_hvym_file(invalid_path)
        assert result['valid'] is False
        assert 'error' in result

    def test_filename_conflict_resolution(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test filename conflict resolution in extract_to_file."""
        # Create token
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="conflict_test.txt"
        )

        hvym_path = os.path.join(temp_dir, "token.hvym")
        token.to_hvym_file(hvym_path)

        # Create existing file with same name
        existing_path = os.path.join(temp_dir, "conflict_test.txt")
        with open(existing_path, 'w') as f:
            f.write("existing content")

        # Extract should handle conflict by adding number
        extracted_path = HVYMDataToken.extract_to_file(hvym_path, receiver_keypair)

        assert extracted_path != existing_path
        assert os.path.exists(extracted_path)
        assert "conflict_test_1.txt" in extracted_path

        # Verify content
        with open(extracted_path, 'rb') as f:
            extracted_data = f.read()
        assert extracted_data == test_file_data

    def test_directory_creation(self, sender_keypair, receiver_keypair, test_file_data, temp_dir):
        """Test automatic directory creation."""
        token = HVYMDataToken(
            senderKeyPair=sender_keypair,
            receiverPub=receiver_keypair.public_key(),
            file_data=test_file_data,
            filename="dir_test.txt"
        )

        # Create path with non-existent subdirectory
        subdir = os.path.join(temp_dir, "new_subdir", "nested")
        hvym_path = os.path.join(subdir, "token.hvym")
        
        # Should create directories automatically
        saved_path = token.to_hvym_file(hvym_path)
        assert os.path.exists(saved_path)
        assert os.path.exists(subdir)

    def test_error_handling_invalid_magic_bytes(self, temp_dir):
        """Test error handling for files with invalid magic bytes."""
        # Create file with invalid magic bytes but otherwise correct structure
        invalid_path = os.path.join(temp_dir, "invalid_magic.hvym")
        with open(invalid_path, 'wb') as f:
            f.write(b'INVALIDX')  # Wrong magic bytes
            f.write(struct.pack('<H', 1))  # Version major
            f.write(struct.pack('<H', 0))  # Version minor
            f.write(struct.pack('<H', 0))  # Flags
            f.write(struct.pack('<I', 20))  # Header length
            f.write(b'{"test": "data"}')  # JSON header

        # Should raise ValueError when trying to read header
        with pytest.raises(ValueError, match="Invalid HVYM file format"):
            HVYMDataToken._read_hvym_header(open(invalid_path, 'rb'))

    def test_header_json_validation(self, temp_dir):
        """Test header JSON validation."""
        # Create file with invalid JSON in header
        invalid_json_path = os.path.join(temp_dir, "invalid_json.hvym")
        with open(invalid_json_path, 'wb') as f:
            f.write(HVYMDataToken.HVYM_MAGIC_BYTES)
            f.write(struct.pack('<H', 1))  # Version major
            f.write(struct.pack('<H', 0))  # Version minor
            f.write(struct.pack('<H', 0))  # Flags
            f.write(struct.pack('<I', 15))  # Header length
            f.write(b'{"invalid": json}')  # Invalid JSON

        # Should raise ValueError for invalid JSON
        with pytest.raises(ValueError, match="Invalid HVYM header JSON"):
            HVYMDataToken._read_hvym_header(open(invalid_json_path, 'rb'))

    def test_missing_header_fields(self, temp_dir):
        """Test validation of required header fields."""
        # Create file with missing required fields
        incomplete_path = os.path.join(temp_dir, "incomplete.hvym")
        incomplete_json = json.dumps({"version": "1.0"}).encode('utf-8')  # Missing other required fields
        
        with open(incomplete_path, 'wb') as f:
            f.write(HVYMDataToken.HVYM_MAGIC_BYTES)
            f.write(struct.pack('<H', 1))  # Version major
            f.write(struct.pack('<H', 0))  # Version minor
            f.write(struct.pack('<H', 0))  # Flags
            f.write(struct.pack('<I', len(incomplete_json)))  # Header length
            f.write(incomplete_json)

        # Should raise ValueError for missing fields
        with pytest.raises(ValueError, match="Missing required field"):
            HVYMDataToken._read_hvym_header(open(incomplete_path, 'rb'))
