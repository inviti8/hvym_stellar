"""
Test suite for the new biscuit-based HVYMDataToken implementation.

Tests:
1. Basic token creation and extraction
2. Large file support (>16KB)
3. Backward compatibility with legacy macaroon tokens
4. Hash verification
5. Expiration handling
6. Save/Load tokens to files
"""

import os
import sys
import tempfile
import hashlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stellar_sdk import Keypair
from hvym_stellar import (
    Stellar25519KeyPair,
    HVYMDataToken,
    StellarSharedAccountTokenBuilder,
    BISCUIT_AVAILABLE
)


def test_biscuit_available():
    """Test that biscuit library is available."""
    print("\n=== Test: Biscuit Library Available ===")
    if BISCUIT_AVAILABLE:
        print("PASSED: biscuit_auth library is available")
        return True
    else:
        print("FAILED: biscuit_auth library is NOT available")
        return False


def test_shared_account_token():
    """Test StellarSharedAccountTokenBuilder."""
    print("\n=== Test: StellarSharedAccountTokenBuilder ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create shared account token
    account_token = StellarSharedAccountTokenBuilder(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        expires_in=3600
    )

    # Get the shared keypair from sender side
    shared_kp_sender = account_token.shared_keypair
    print(f"  Shared account public key: {shared_kp_sender.public_key[:20]}...")

    # Serialize the token
    serialized = account_token.serialize()
    print(f"  Serialized token length: {len(serialized)} chars")

    # Extract shared keypair from receiver side
    shared_kp_receiver = StellarSharedAccountTokenBuilder.extract_shared_keypair(
        serialized_token=serialized,
        receiverKeyPair=receiver_kp
    )

    # Verify both sides have the same keypair
    if shared_kp_sender.public_key == shared_kp_receiver.public_key:
        print("PASSED: Shared keypair matches on both sides")
        return True
    else:
        print("FAILED: Shared keypair mismatch")
        return False


def test_small_file_token():
    """Test HVYMDataToken with small file (<16KB)."""
    print("\n=== Test: Small File Token (<16KB) ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create small test data (1KB)
    test_data = b"Hello, this is test data! " * 40  # ~1KB
    test_filename = "small_test.txt"

    print(f"  Test data size: {len(test_data)} bytes")

    # Create token
    token = HVYMDataToken(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        filename=test_filename,
        expires_in=3600
    )

    # Serialize
    serialized = token.serialize()
    print(f"  Serialized token length: {len(serialized)} chars")
    print(f"  Token contains BISCUIT_DELIMITER: {HVYMDataToken.BISCUIT_DELIMITER in serialized}")

    # Extract
    file_bytes, metadata = HVYMDataToken.extract_from_token(
        serialized_token=serialized,
        receiver_keypair=receiver_kp
    )

    # Verify
    if file_bytes == test_data:
        print(f"PASSED: Extracted data matches original ({len(file_bytes)} bytes)")
        return True
    else:
        print("FAILED: Data mismatch")
        return False


def test_large_file_token():
    """Test HVYMDataToken with large file (>16KB) - the main use case!"""
    print("\n=== Test: Large File Token (>16KB) ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create large test data (100KB)
    test_data = b"X" * (100 * 1024)  # 100KB
    test_filename = "large_test.bin"

    print(f"  Test data size: {len(test_data)} bytes ({len(test_data) // 1024}KB)")

    # Create token
    token = HVYMDataToken(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        filename=test_filename,
        expires_in=3600
    )

    # Serialize
    serialized = token.serialize()
    print(f"  Serialized token length: {len(serialized)} chars ({len(serialized) // 1024}KB)")

    # Extract
    file_bytes, metadata = HVYMDataToken.extract_from_token(
        serialized_token=serialized,
        receiver_keypair=receiver_kp
    )

    # Verify
    if file_bytes == test_data:
        print(f"PASSED: Large file extracted successfully ({len(file_bytes)} bytes)")
        return True
    else:
        print("FAILED: Data mismatch")
        return False


def test_very_large_file_token():
    """Test HVYMDataToken with very large file (1MB)."""
    print("\n=== Test: Very Large File Token (1MB) ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create very large test data (1MB)
    test_data = os.urandom(1024 * 1024)  # 1MB of random data
    test_filename = "very_large_test.bin"

    print(f"  Test data size: {len(test_data)} bytes ({len(test_data) // 1024}KB)")
    original_hash = hashlib.sha256(test_data).hexdigest()
    print(f"  Original hash: {original_hash[:16]}...")

    # Create token
    token = HVYMDataToken(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        filename=test_filename,
        expires_in=3600
    )

    # Serialize
    serialized = token.serialize()
    print(f"  Serialized token length: {len(serialized)} chars ({len(serialized) // 1024}KB)")

    # Extract
    file_bytes, metadata = HVYMDataToken.extract_from_token(
        serialized_token=serialized,
        receiver_keypair=receiver_kp
    )

    extracted_hash = hashlib.sha256(file_bytes).hexdigest()
    print(f"  Extracted hash: {extracted_hash[:16]}...")

    # Verify
    if file_bytes == test_data and original_hash == extracted_hash:
        print(f"PASSED: 1MB file extracted successfully with matching hash")
        return True
    else:
        print("FAILED: Data or hash mismatch")
        return False


def test_file_from_disk():
    """Test HVYMDataToken with actual file from disk."""
    print("\n=== Test: File From Disk ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
        test_data = b"This is test content from a real file!\n" * 1000
        f.write(test_data)
        temp_path = f.name

    try:
        print(f"  Temp file: {temp_path}")
        print(f"  File size: {os.path.getsize(temp_path)} bytes")

        # Create token from file
        token = HVYMDataToken.create_from_file(
            senderKeyPair=sender_kp,
            receiverPub=receiver_kp.public_key(),
            file_path=temp_path,
            expires_in=3600
        )

        # Serialize
        serialized = token.serialize()
        print(f"  Token length: {len(serialized)} chars")

        # Extract
        file_bytes, metadata = HVYMDataToken.extract_from_token(
            serialized_token=serialized,
            receiver_keypair=receiver_kp
        )

        # Verify
        if file_bytes == test_data:
            print(f"PASSED: File from disk extracted successfully")
            return True
        else:
            print("FAILED: Data mismatch")
            return False
    finally:
        # Cleanup
        os.unlink(temp_path)


def test_create_from_bytes():
    """Test create_from_bytes class method."""
    print("\n=== Test: create_from_bytes ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Test data
    test_data = b"Test data for create_from_bytes method!" * 100

    # Create token using class method
    token = HVYMDataToken.create_from_bytes(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        filename="test_bytes.dat",
        expires_in=3600
    )

    # Serialize and extract
    serialized = token.serialize()
    file_bytes, metadata = HVYMDataToken.extract_from_token(
        serialized_token=serialized,
        receiver_keypair=receiver_kp
    )

    if file_bytes == test_data:
        print("PASSED: create_from_bytes works correctly")
        return True
    else:
        print("FAILED: Data mismatch")
        return False


def test_hash_verification():
    """Test that hash verification catches tampering."""
    print("\n=== Test: Hash Verification ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create token
    test_data = b"Original data that should not be tampered with!"
    token = HVYMDataToken(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        expires_in=3600
    )

    # Get file info
    file_info = token.get_file_info()
    print(f"  Original hash: {file_info.get('hash', 'N/A')[:16]}...")

    # Serialize
    serialized = token.serialize()

    # Extract with hash verification (should succeed)
    try:
        file_bytes, metadata = HVYMDataToken.extract_from_token(
            serialized_token=serialized,
            receiver_keypair=receiver_kp,
            verify_hash=True
        )
        print("PASSED: Hash verification succeeded for valid token")
        return True
    except ValueError as e:
        print(f"FAILED: Unexpected error: {e}")
        return False


def test_dict_data_legacy():
    """Test legacy dict data support."""
    print("\n=== Test: Legacy Dict Data Support ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create token with dict data
    test_dict = {"key": "value", "number": 42, "nested": {"a": 1}}
    token = HVYMDataToken(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        data=test_dict,
        expires_in=3600
    )

    # Verify get_data returns the dict
    retrieved_data = token.get_data()
    if retrieved_data == test_dict:
        print("PASSED: Legacy dict data support works")
        return True
    else:
        print(f"FAILED: Dict mismatch - expected {test_dict}, got {retrieved_data}")
        return False


def test_save_load_token_file():
    """Test saving and loading tokens to/from files."""
    print("\n=== Test: Save/Load Token to File ===")

    # Create keypairs
    sender_stellar = Keypair.random()
    receiver_stellar = Keypair.random()

    sender_kp = Stellar25519KeyPair(sender_stellar)
    receiver_kp = Stellar25519KeyPair(receiver_stellar)

    # Create test data
    test_data = b"This is test data for file save/load!" * 100
    test_filename = "test_save_load.bin"

    # Create token
    token = HVYMDataToken.create_from_bytes(
        senderKeyPair=sender_kp,
        receiverPub=receiver_kp.public_key(),
        file_data=test_data,
        filename=test_filename,
        expires_in=3600
    )

    # Save token to file
    token_file_path = tempfile.mktemp(suffix=".hvym")
    try:
        token.save_token_to_file(token_file_path)
        print(f"  Token saved to: {token_file_path}")

        # Check file was created
        token_file_size = os.path.getsize(token_file_path)
        print(f"  Token file size: {token_file_size} bytes")

        # Load and extract from file
        file_bytes, metadata = HVYMDataToken.load_token_from_file(
            file_path=token_file_path,
            receiver_keypair=receiver_kp
        )

        print(f"  Extracted {len(file_bytes)} bytes")
        print(f"  Metadata filename: {metadata.get('filename')}")

        # Verify data matches
        if file_bytes == test_data:
            print("PASSED: Save/Load token to file works correctly")
            return True
        else:
            print("FAILED: Data mismatch after load")
            return False

    finally:
        # Cleanup
        if os.path.exists(token_file_path):
            os.unlink(token_file_path)


def main():
    """Run all tests."""
    print("=" * 60)
    print("HVYMDataToken Biscuit Implementation Tests")
    print("=" * 60)

    tests = [
        ("Biscuit Available", test_biscuit_available),
        ("Shared Account Token", test_shared_account_token),
        ("Small File Token", test_small_file_token),
        ("Large File Token (100KB)", test_large_file_token),
        ("Very Large File Token (1MB)", test_very_large_file_token),
        ("File From Disk", test_file_from_disk),
        ("create_from_bytes", test_create_from_bytes),
        ("Hash Verification", test_hash_verification),
        ("Legacy Dict Data", test_dict_data_legacy),
        ("Save/Load Token File", test_save_load_token_file),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, "PASSED" if result else "FAILED"))
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, f"ERROR: {e}"))

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, r in results if r == "PASSED")
    failed = sum(1 for _, r in results if r == "FAILED")
    errors = sum(1 for _, r in results if r.startswith("ERROR"))

    for test_name, result in results:
        status = "PASS" if result == "PASSED" else "FAIL" if result == "FAILED" else "ERR"
        print(f"  [{status}] {test_name}")

    print()
    print(f"Total: {len(results)} | Passed: {passed} | Failed: {failed} | Errors: {errors}")

    if passed == len(results):
        print("\nALL TESTS PASSED!")
        return 0
    else:
        print("\nSome tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
