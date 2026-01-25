import time
import unittest
import warnings
import secrets
import hashlib
from stellar_sdk import Keypair
from hvym_stellar import *


class TestStellarSharedKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender_stellar_kp = Keypair.random()
        cls.reciever_stellar_kp = Keypair.random()
        
        # Stellar keys must be converted to be compatible format for ECDH
        cls.sender_kp = Stellar25519KeyPair(cls.sender_stellar_kp)
        cls.reciever_kp = Stellar25519KeyPair(cls.reciever_stellar_kp)

    def test_deterministic_shared_secret(self):
        """Test that shared_secret() is deterministic by default (raw ECDH)."""
        sk1 = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        sk2 = StellarSharedKey(self.reciever_kp, self.sender_kp.public_key())
        
        # Default behavior should be deterministic
        secret1 = sk1.shared_secret()
        secret2 = sk2.shared_secret()
        
        self.assertEqual(secret1, secret2)
        # Should equal raw ECDH secret
        self.assertEqual(secret1, sk1._box.shared_key())
        self.assertEqual(secret2, sk2._box.shared_key())

    def test_salt_parameter_behavior(self):
        """Test salt parameter functionality."""
        sk1 = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        sk2 = StellarSharedKey(self.reciever_kp, self.sender_kp.public_key())
        
        # Test with specific salt
        test_salt = secrets.token_bytes(32)
        
        key1_with_salt = sk1.shared_secret(salt=test_salt)
        key2_with_salt = sk2.shared_secret(salt=test_salt)
        
        self.assertEqual(key1_with_salt, key2_with_salt)
        # Should be different from deterministic key
        deterministic_key = sk1.shared_secret()
        self.assertNotEqual(key1_with_salt, deterministic_key)

    def test_nonce_parameter_behavior(self):
        """Test nonce parameter functionality (currently unused but accepted)."""
        # Sender creates shared key
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        
        test_salt = secrets.token_bytes(32)
        test_nonce = secrets.token_bytes(24)
        
        # Sender extracts salt/nonce and passes to receiver
        # Receiver creates shared key with provided salt/nonce
        receiver_key = StellarSharedKey(self.reciever_kp, self.sender_kp.public_key())
        
        # Both should produce same key with same salt/nonce
        key_from_sender = sender_key.shared_secret(salt=test_salt, nonce=test_nonce)
        key_from_receiver = receiver_key.shared_secret(salt=test_salt, nonce=test_nonce)
        
        self.assertEqual(key_from_sender, key_from_receiver)
        
        # Nonce doesn't affect result currently, but should be accepted
        different_nonce = secrets.token_bytes(24)
        key_with_different_nonce = receiver_key.shared_secret(salt=test_salt, nonce=different_nonce)
        
        self.assertEqual(key_from_sender, key_with_different_nonce)

    def test_cross_class_consistency(self):
        """Test that StellarSharedKey and StellarSharedDecryption can derive same keys."""
        encrypt_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        decrypt_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        test_salt = secrets.token_bytes(32)
        
        # Both should derive same key with same salt
        key_from_encrypt = encrypt_key.shared_secret(salt=test_salt)
        key_from_decrypt = decrypt_key.shared_secret(salt=test_salt)
        
        self.assertEqual(key_from_encrypt, key_from_decrypt)

    def test_utility_functions(self):
        """Test salt/nonce/ciphertext extraction utility functions."""
        shared_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        message = b"test message for encryption"
        
        encrypted = shared_key.encrypt(message)
        
        # Extract components
        salt = extract_salt_from_encrypted(encrypted)
        nonce = extract_nonce_from_encrypted(encrypted)
        ciphertext = extract_ciphertext_from_encrypted(encrypted)
        
        # Verify components are not None
        self.assertIsNotNone(salt)
        self.assertIsNotNone(nonce)
        self.assertIsNotNone(ciphertext)
        
        # Verify correct lengths
        self.assertEqual(len(salt), 32)  # 32 bytes salt
        self.assertEqual(len(nonce), 24)  # NaCl NONCE_SIZE

    def test_encryption_key_reconstruction(self):
        """Test that we can reconstruct the exact key used for encryption."""
        shared_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        message = b"test message for encryption"
        
        # Encrypt
        encrypted = shared_key.encrypt(message)
        
        # Extract salt
        salt = extract_salt_from_encrypted(encrypted)
        
        # Reconstruct the same key
        reconstructed_key = shared_key.shared_secret(salt=salt)
        
        # Verify it's the same as what was used for encryption
        expected_key = shared_key._derive_key(salt=salt)
        
        self.assertEqual(reconstructed_key, expected_key)

    def test_hash_consistency(self):
        """Test hash methods work with new parameters."""
        encrypt_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        decrypt_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        test_salt = secrets.token_bytes(32)
        
        # Both should produce same hash with same salt
        hash1 = encrypt_key.hash_of_shared_secret(salt=test_salt)
        hash2 = decrypt_key.hash_of_shared_secret(salt=test_salt)
        
        self.assertEqual(hash1, hash2)
        
        # Hash should be different from deterministic hash
        deterministic_hash = encrypt_key.hash_of_shared_secret()
        self.assertNotEqual(hash1, deterministic_hash)

    def test_deprecation_warning(self):
        """Test that random_salt parameter shows deprecation warning."""
        sk = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            # Should trigger deprecation warning
            sk.shared_secret(random_salt=True)
            
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[0].category, DeprecationWarning))
            self.assertIn("random_salt parameter is deprecated", str(w[0].message))

    def test_shared_secret_as_hex_with_parameters(self):
        """Test shared_secret_as_hex with new parameters."""
        sk = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        
        test_salt = secrets.token_bytes(32)
        
        # Test with salt parameter
        hex_with_salt = sk.shared_secret_as_hex(salt=test_salt)
        bytes_with_salt = sk.shared_secret(salt=test_salt)
        
        self.assertEqual(hex_with_salt, bytes_with_salt.hex())
        
        # Test deterministic behavior
        hex_deterministic = sk.shared_secret_as_hex()
        bytes_deterministic = sk.shared_secret()
        
        self.assertEqual(hex_deterministic, bytes_deterministic.hex())

    def test_sender_receiver_model(self):
        """Test the natural sender-receiver model with salt/nonce extraction."""
        # Sender creates shared key and encrypts data
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        message = b"Secret message from sender"
        
        # Sender encrypts the message
        encrypted = sender_key.encrypt(message)
        
        # Sender extracts salt and nonce from encrypted data
        salt = extract_salt_from_encrypted(encrypted)
        nonce = extract_nonce_from_encrypted(encrypted)
        
        # Sender passes salt/nonce to receiver (could be via token, message, etc.)
        # Receiver creates shared key with received salt/nonce
        receiver_key = StellarSharedKey(self.reciever_kp, self.sender_kp.public_key())
        
        # Both should derive the same key
        sender_derived_key = sender_key.shared_secret(salt=salt, nonce=nonce)
        receiver_derived_key = receiver_key.shared_secret(salt=salt, nonce=nonce)
        
        self.assertEqual(sender_derived_key, receiver_derived_key)
        
        # Receiver should be able to decrypt the message
        receiver_decrypt_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        decrypted = receiver_decrypt_key.decrypt(encrypted)
        
        self.assertEqual(decrypted, message)
        
        # Verify the derived key matches what was used for encryption
        expected_key = sender_key._derive_key(salt=salt)
        self.assertEqual(sender_derived_key, expected_key)

    def test_asymmetric_methods(self):
        """Test new asymmetric methods."""
        # Test asymmetric shared secret consistency
        encrypt_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        decrypt_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        asym_secret1 = encrypt_key.asymmetric_shared_secret()
        asym_secret2 = decrypt_key.asymmetric_shared_secret()
        
        self.assertEqual(asym_secret1, asym_secret2)
        self.assertEqual(len(asym_secret1), 32)  # X25519 produces 32-byte secrets
        
        # Test asymmetric hex encoding
        asym_hex1 = encrypt_key.asymmetric_shared_secret_as_hex()
        asym_hex2 = decrypt_key.asymmetric_shared_secret_as_hex()
        
        self.assertEqual(asym_hex1, asym_hex2)
        self.assertEqual(asym_hex1, asym_secret1.hex())
        
        # Test asymmetric hash
        asym_hash1 = encrypt_key.asymmetric_hash_of_shared_secret()
        asym_hash2 = decrypt_key.asymmetric_hash_of_shared_secret()
        
        self.assertEqual(asym_hash1, asym_hash2)
        
        # Should be SHA-256 of raw secret
        import hashlib
        expected_hash = hashlib.sha256(asym_secret1).hexdigest()
        self.assertEqual(asym_hash1, expected_hash)

    def test_proper_asymmetric_encryption(self):
        """Test that new asymmetric encryption methods work properly."""
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        receiver_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        message = b"Test message for proper asymmetric encryption"
        
        # Test new asymmetric methods
        encrypted = sender_key.asymmetric_encrypt(message)
        decrypted = receiver_key.asymmetric_decrypt(encrypted)
        
        self.assertEqual(decrypted, message)
        
        # Verify it's using standard X25519 (not self-encryption)
        self.assertEqual(sender_key._box.shared_key(), receiver_key._box.shared_key())
        
        # Verify it's different from hybrid approach
        hybrid_encrypted = sender_key.encrypt(message)
        hybrid_decrypted = receiver_key.decrypt(hybrid_encrypted)
        
        self.assertEqual(hybrid_decrypted, message)
        
        # Verify approaches are different (should be different ciphertexts)
        self.assertNotEqual(encrypted, hybrid_encrypted)
        
        # Both should work with their respective decryption methods
        self.assertEqual(decrypted, message)
        self.assertEqual(hybrid_decrypted, message)

    def test_hybrid_encryption_compatibility(self):
        """Test that hybrid encryption (original behavior) works correctly."""
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        receiver_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        message = b"Test message for hybrid compatibility"
        
        # Test hybrid approach (original behavior)
        encrypted = sender_key.encrypt(message)
        decrypted = receiver_key.decrypt(encrypted)
        
        self.assertEqual(decrypted, message)
        
        # Verify it's using derived key approach (self-encryption)
        derived_key = sender_key._derive_key()
        private_key = PrivateKey(derived_key)
        public_key = PublicKey(derived_key)
        box = Box(private_key, public_key)
        
        # The box should be different from the standard X25519 box
        self.assertNotEqual(sender_key._box.shared_key(), box.shared_key())
        
        # But the derived key should be used for encryption
        self.assertEqual(derived_key, hashlib.sha256(sender_key._salt + sender_key._box.shared_key()).digest())

    def test_cross_method_consistency(self):
        """Test consistency between asymmetric and derived methods."""
        sk = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        dk = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        # Asymmetric methods should match
        self.assertEqual(sk.asymmetric_shared_secret(), dk.asymmetric_shared_secret())
        self.assertEqual(sk.asymmetric_shared_secret_as_hex(), dk.asymmetric_shared_secret_as_hex())
        self.assertEqual(sk.asymmetric_hash_of_shared_secret(), dk.asymmetric_hash_of_shared_secret())
        
        # Derived methods should still work
        salt = secrets.token_bytes(32)
        self.assertEqual(sk.shared_secret(salt=salt), dk.shared_secret(salt=salt))
        self.assertEqual(sk.shared_secret_as_hex(salt=salt), dk.shared_secret_as_hex(salt=salt))
        self.assertEqual(sk.hash_of_shared_secret(salt=salt), dk.hash_of_shared_secret(salt=salt))

    def test_backward_compatibility(self):
        """Test that existing code still works without changes."""
        sk = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        
        # Old-style calls should still work
        key1 = sk.shared_secret()
        hex1 = sk.shared_secret_as_hex()
        hash1 = sk.hash_of_shared_secret()
        
        # Should be deterministic
        self.assertEqual(key1, sk._box.shared_key())
        self.assertEqual(hex1, key1.hex())
        self.assertIsInstance(hash1, str)
        
        # Test decryption class backward compatibility
        dk = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        key2 = dk.shared_secret()
        hex2 = dk.shared_secret_as_hex()
        hash2 = dk.hash_of_shared_secret()
        
        self.assertEqual(key2, dk._box.shared_key())
        self.assertEqual(hex2, key2.hex())
        self.assertIsInstance(hash2, str)

    def test_signature_verification_with_valid_address(self):
        """Test signature verification with valid sender address."""
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        receiver_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        message = b"Test message for signature verification"
        encrypted = sender_key.encrypt(message)
        
        # Test decryption WITH valid from_address (should succeed)
        sender_address = self.sender_stellar_kp.public_key
        decrypted = receiver_key.decrypt(encrypted, from_address=sender_address)
        
        self.assertEqual(decrypted, message)
        
    def test_signature_verification_with_invalid_address(self):
        """Test signature verification with invalid sender address."""
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        receiver_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        message = b"Test message for signature verification"
        encrypted = sender_key.encrypt(message)
        
        # Test decryption WITH invalid from_address (should fail)
        wrong_kp = Keypair.random()
        wrong_address = wrong_kp.public_key
        
        with self.assertRaises(ValueError) as context:
            receiver_key.decrypt(encrypted, from_address=wrong_address)
        
        self.assertIn("Signature verification failed", str(context.exception))
        
    def test_signature_verification_without_address(self):
        """Test decryption without from_address (backward compatibility)."""
        sender_key = StellarSharedKey(self.sender_kp, self.reciever_kp.public_key())
        receiver_key = StellarSharedDecryption(self.reciever_kp, self.sender_kp.public_key())
        
        message = b"Test message for signature verification"
        encrypted = sender_key.encrypt(message)
        
        # Test decryption WITHOUT from_address (should succeed for backward compatibility)
        decrypted = receiver_key.decrypt(encrypted)
        
        self.assertEqual(decrypted, message)


def run_legacy_tests():
    """Run the original tests for backward compatibility."""
    sender_stellar_kp = Keypair.random()
    reciever_stellar_kp = Keypair.random()

    ##Stellar keys must be converted to be compatible format for ECDH
    sender_kp = Stellar25519KeyPair(sender_stellar_kp)
    reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)

    print('public key:')
    print(reciever_stellar_kp.public_key)
    print(reciever_kp.public_key())

    ##Create the encryption object
    sharedKey = StellarSharedKey(sender_kp, reciever_kp.public_key())
    txt = sender_stellar_kp.secret.encode('utf-8')
    print('original secret:')
    print(txt)

    encrypted = sharedKey.encrypt(txt)
    print('encrypted:')
    print(encrypted.decode('utf-8'))

    ##Create the decryption object
    sharedDecrypt = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
    ##Decrypt
    decrypted = sharedDecrypt.decrypt(encrypted)

    print('decrypted secret:')
    print(decrypted)

    ##Token creation and verification
    caveats = {
        'test' : 'pass'
    }

    ##create a new access token and serialize it
    token = StellarSharedKeyTokenBuilder(sender_kp, reciever_kp.public_key(), token_type=TokenType.ACCESS, caveats=caveats)
    serialized_token = token.serialize()

    print(token.inspect())
    print(serialized_token)

    wrong_caveats = {
        'test' : 'test',
        'test' : 'fail'
    }

    ##Create token verifier and check validity of token
    tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.ACCESS, caveats=caveats)

    print(tokenVerifier.valid())##>> True

    tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.ACCESS, caveats=wrong_caveats)

    print(tokenVerifier.valid())##>> False

    tokenVerifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, token_type=TokenType.SECRET, caveats=caveats)

    print(tokenVerifier.valid())##>> False

    ##Try to use verify token with a different key
    attacker_stellar_kp = Keypair.random()
    attacker_kp = Stellar25519KeyPair(attacker_stellar_kp)

    tokenVerifier = StellarSharedKeyTokenVerifier(attacker_kp, serialized_token, token_type=TokenType.ACCESS, caveats=caveats)

    print(tokenVerifier.valid())##>> False

    ##Create the decryption object
    sharedDecrypt = StellarSharedDecryption(attacker_kp, sender_kp.public_key())
    ##Decrypt
    try:
        txt = sharedDecrypt.decrypt(encrypted)
        print(txt)
    except:
        print('Cant Decrypt!!')

    ##create a new secret token and serialize it
    abstract_acct_stellar_kp = Keypair.random()
    abstract_acct_kp = Stellar25519KeyPair(abstract_acct_stellar_kp)
    token = StellarSharedKeyTokenBuilder(sender_kp, abstract_acct_kp.public_key(), token_type=TokenType.SECRET, caveats=caveats, secret=abstract_acct_stellar_kp.secret)
    serialized_token = token.serialize()
    
    print(token.inspect())
    print(serialized_token)

    ##Create token verifier and check validity of token and retrieve it's secret
    tokenVerifier = StellarSharedKeyTokenVerifier(abstract_acct_kp, serialized_token, token_type=TokenType.SECRET, caveats=caveats)

    print('Retrieve the senders public key:')
    print(tokenVerifier.sender_pub())

    print(tokenVerifier.valid())##>> True
    print('Do secrets match?:')
    print(abstract_acct_stellar_kp.secret)
    print(tokenVerifier.secret())


def run_timestamp_tests():
    """Run tests for the new timestamp functionality."""
    print("\n=== Testing Timestamp Functionality ===")
    
    # Setup test keys
    sender_stellar_kp = Keypair.random()
    reciever_stellar_kp = Keypair.random()
    sender_kp = Stellar25519KeyPair(sender_stellar_kp)
    reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)
    
    # Test 1: Token with expiration
    print("\nTest 1: Token with expiration")
    token = StellarSharedKeyTokenBuilder(
        sender_kp, 
        reciever_kp.public_key(), 
        token_type=TokenType.ACCESS, 
        caveats={"test": "pass"},
        expires_in=3600  # 1 hour expiration
    )
    serialized_token = token.serialize()
    verifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, TokenType.ACCESS, {"test": "pass"})
    
    print(f"Token expires at: {verifier._get_expiration_time()}")
    print(f"Is expired: {verifier.is_expired()}")
    print(f"Is valid: {verifier.valid()}")
    
    # Test 2: Expired token
    print("\nTest 2: Expired token")
    token = StellarSharedKeyTokenBuilder(
        sender_kp, 
        reciever_kp.public_key(), 
        token_type=TokenType.ACCESS, 
        caveats={"test": "pass"},
        expires_in=-1  # Already expired
    )
    serialized_token = token.serialize()
    verifier = StellarSharedKeyTokenVerifier(reciever_kp, serialized_token, TokenType.ACCESS, {"test": "pass"})
    
    print(f"Is expired: {verifier.is_expired()}")
    print(f"Is valid: {verifier.valid()}")
    
    # Test 3: Token with max age
    print("\nTest 3: Token with max age validation")
    token = StellarSharedKeyTokenBuilder(
        sender_kp, 
        reciever_kp.public_key(), 
        token_type=TokenType.ACCESS, 
        caveats={"test": "pass"}
    )
    serialized_token = token.serialize()
    
    # Verify with max age of 1 second
    verifier = StellarSharedKeyTokenVerifier(
        reciever_kp, 
        serialized_token, 
        TokenType.ACCESS, 
        {"test": "pass"},
        max_age_seconds=1  # Max age 1 second
    )
    
    print("Verifying immediately (should pass):", verifier.valid())
    
    # Wait 2 seconds
    time.sleep(2)
    
    # Verify again (should fail due to max age)
    verifier = StellarSharedKeyTokenVerifier(
        reciever_kp, 
        serialized_token, 
        TokenType.ACCESS, 
        {"test": "pass"},
        max_age_seconds=1  # Max age 1 second
    )
    print("Verifying after delay (should fail):", verifier.valid())
    
    # Test 4: Secret token with expiration
    print("\nTest 4: Secret token with expiration")
    secret_text = "my-secret-data"
    token = StellarSharedKeyTokenBuilder(
        sender_kp, 
        reciever_kp.public_key(), 
        token_type=TokenType.SECRET, 
        caveats={"test": "pass"},
        secret=secret_text,
        expires_in=3600  # 1 hour expiration
    )
    serialized_token = token.serialize()
    verifier = StellarSharedKeyTokenVerifier(
        reciever_kp, 
        serialized_token, 
        TokenType.SECRET, 
        {"test": "pass"}
    )
    
    print(f"Is expired: {verifier.is_expired()}")
    print(f"Is valid: {verifier.valid()}")
    print(f"Secret matches: {verifier.secret() == secret_text}")


def test_robust_decryption():
    """Test the robustness of the decryption with different input types and line endings."""
    print("\n=== Testing Robust Decryption ===")
    
    # Setup test keys
    sender_stellar_kp = Keypair.random()
    reciever_stellar_kp = Keypair.random()
    sender_kp = Stellar25519KeyPair(sender_stellar_kp)
    reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)
    
    # Test data
    test_secret = b"test_secret_data_123"
    
    # Create shared key and encrypt
    shared_key = StellarSharedKey(sender_kp, reciever_kp.public_key())
    encrypted = shared_key.encrypt(test_secret)
    
    # Create decryption object
    shared_decrypt = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
    
    # Test cases
    test_cases = [
        ("Normal case", encrypted),
        ("String input", encrypted.decode('utf-8')),
        ("With newline", encrypted + b'\n'),
        ("With Windows newline", encrypted + b'\r\n'),
        ("With spaces", b'   ' + encrypted + b'   '),
    ]
    
    for name, test_input in test_cases:
        print(f"\nTest: {name}")
        try:
            decrypted = shared_decrypt.decrypt(test_input)
            assert decrypted == test_secret, f"Decrypted data does not match original for {name}"
            print(f"✅ Success: {name}")
        except Exception as e:
            print(f"❌ Failed {name}: {str(e)}")
            raise
    
    print("\nAll robust decryption tests passed!")


def test_comprehensive_salt_nonce_functionality():
    """Test comprehensive salt/nonce functionality using sender-receiver model."""
    print("\n=== Testing Comprehensive Salt/Nonce Functionality ===")
    
    # Setup test keys
    sender_stellar_kp = Keypair.random()
    reciever_stellar_kp = Keypair.random()
    sender_kp = Stellar25519KeyPair(sender_stellar_kp)
    reciever_kp = Stellar25519KeyPair(reciever_stellar_kp)
    
    # Test 1: Basic salt parameter functionality
    print("\nTest 1: Basic salt parameter functionality")
    sk1 = StellarSharedKey(sender_kp, reciever_kp.public_key())
    sk2 = StellarSharedKey(reciever_kp, sender_kp.public_key())
    
    test_salt = secrets.token_bytes(32)
    
    key1 = sk1.shared_secret(salt=test_salt)
    key2 = sk2.shared_secret(salt=test_salt)
    
    print(f"Keys with same salt match: {key1 == key2}")
    print(f"Keys different from deterministic: {key1 != sk1.shared_secret()}")
    
    # Test 2: Cross-class consistency
    print("\nTest 2: Cross-class consistency")
    encrypt_key = StellarSharedKey(sender_kp, reciever_kp.public_key())
    decrypt_key = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
    
    key_from_encrypt = encrypt_key.shared_secret(salt=test_salt)
    key_from_decrypt = decrypt_key.shared_secret(salt=test_salt)
    
    print(f"Cross-class keys match: {key_from_encrypt == key_from_decrypt}")
    
    # Test 3: Sender-Receiver Model (Natural Workflow)
    print("\nTest 3: Sender-Receiver Model (Natural Workflow)")
    
    # Sender creates shared key and encrypts message
    sender_key = StellarSharedKey(sender_kp, reciever_kp.public_key())
    message = b"Secret message from sender"
    encrypted = sender_key.encrypt(message)
    
    # Sender extracts salt/nonce and passes to receiver
    salt = extract_salt_from_encrypted(encrypted)
    nonce = extract_nonce_from_encrypted(encrypted)
    
    # Receiver creates shared key with received salt/nonce
    receiver_key = StellarSharedKey(reciever_kp, sender_kp.public_key())
    
    # Both derive same key
    sender_derived = sender_key.shared_secret(salt=salt, nonce=nonce)
    receiver_derived = receiver_key.shared_secret(salt=salt, nonce=nonce)
    
    print(f"Sender-Receiver keys match: {sender_derived == receiver_derived}")
    
    # Receiver can decrypt the message
    receiver_decrypt = StellarSharedDecryption(reciever_kp, sender_kp.public_key())
    decrypted = receiver_decrypt.decrypt(encrypted)
    
    print(f"Message decrypted correctly: {decrypted == message}")
    
    # Test 4: Utility functions
    print("\nTest 4: Utility functions")
    print(f"Salt extracted: {len(salt)} bytes")
    print(f"Nonce extracted: {len(nonce)} bytes")
    print(f"Ciphertext extracted: {len(extract_ciphertext_from_encrypted(encrypted))} bytes")
    
    # Test 5: Hash consistency
    print("\nTest 5: Hash consistency")
    hash1 = encrypt_key.hash_of_shared_secret(salt=test_salt)
    hash2 = decrypt_key.hash_of_shared_secret(salt=test_salt)
    
    print(f"Hashes match: {hash1 == hash2}")
    print(f"Hashes different from deterministic: {hash1 != encrypt_key.hash_of_shared_secret()}")
    
    # Test 6: Hex encoding with parameters
    print("\nTest 6: Hex encoding with parameters")
    hex_with_salt = encrypt_key.shared_secret_as_hex(salt=test_salt)
    bytes_with_salt = encrypt_key.shared_secret(salt=test_salt)
    
    print(f"Hex encoding correct: {hex_with_salt == bytes_with_salt.hex()}")
    
    print("\n✅ All comprehensive salt/nonce tests completed!")


if __name__ == "__main__":
    # Run legacy tests
    run_legacy_tests()
    
    # Run timestamp tests
    run_timestamp_tests()
    
    # Run robust decryption tests
    test_robust_decryption()
    
    # Run comprehensive salt/nonce tests
    test_comprehensive_salt_nonce_functionality()
    
    # Run the unittest test suite
    unittest.main()
