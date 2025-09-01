import time
import unittest
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


if __name__ == "__main__":
    # Run legacy tests
    run_legacy_tests()
    
    # Run timestamp tests
    run_timestamp_tests()

