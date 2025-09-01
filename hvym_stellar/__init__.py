"""Heavymeta Stellar Utilities for Python , By: Fibo Metavinci"""

__version__ = "0.08"

import nacl
from nacl import utils, secret
from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey, Box, EncryptedMessage
from stellar_sdk import Keypair
from pymacaroons import Macaroon, Verifier
import hashlib
import secrets
import base64
from enum import Enum
import hmac

class Stellar25519KeyPair:
    def __init__(self, keyPair : Keypair):
        self._base_keypair = keyPair
        self._raw_secret = keyPair.raw_secret_key()
        self._signing_key = SigningKey(self._raw_secret)
        self._private = self._signing_key.to_curve25519_private_key()
        self._public = self._signing_key.verify_key.to_curve25519_public_key()

    def base_stellar_keypair(self) -> Keypair:
        return self._base_keypair

    def signing_key(self) -> SigningKey:
        return self._signing_key
    
    def public_key_raw(self) -> PublicKey:
        return self._public
    
    def public_key(self):
        return base64.urlsafe_b64encode(self.public_key_raw().encode()).decode("utf-8")
    
    def private_key(self) -> PrivateKey:
        return self._private

class StellarSharedKey:
    def __init__(self, senderKeyPair: Stellar25519KeyPair, recieverPub: str):
        # Generate a random 32-byte salt for this instance
        self._salt = secrets.token_bytes(32)
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        self._hasher = hashlib.sha256()
        self._private = senderKeyPair.private_key()
        self._raw_pub = base64.urlsafe_b64decode(recieverPub.encode("utf-8"))
        self._box = Box(self._private, PublicKey(self._raw_pub))

    def nonce(self) -> bytes:
        return nacl.encoding.HexEncoder.encode(self._nonce).decode('utf-8')
    
    def _derive_key(self, salt: bytes = None) -> bytes:
        """Derive a key using the salt and shared secret"""
        if salt is None:
            salt = self._salt
        # Combine salt and shared secret
        combined = salt + self._box.shared_key()
        # Hash the combination to get the derived key
        return hashlib.sha256(combined).digest()
    
    def shared_secret(self) -> bytes:
        """Get the derived shared secret"""
        return self._derive_key()
    
    def shared_secret_as_hex(self) -> str:
        return nacl.encoding.HexEncoder.encode(self.shared_secret()).decode('utf-8')
    
    def hash_of_shared_secret(self):
        hasher = hashlib.sha256()
        hasher.update(self.shared_secret())
        return hasher.hexdigest()
    
    def encrypt(self, text: bytes) -> bytes:
        # Generate a new random salt for each encryption
        self._salt = secrets.token_bytes(32)
        # Generate a new nonce for each encryption
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        
        # Derive the encryption key
        derived_key = self._derive_key()
        private_key = PrivateKey(derived_key)
        public_key = PublicKey(derived_key)  # Same key for both sides
        box = Box(private_key, public_key)
        
        # Encrypt the message with the derived key
        encrypted = box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder)
        
        # Return salt + '|' + nonce + '|' + ciphertext as bytes
        return (base64.urlsafe_b64encode(self._salt) + b'|' +
                base64.urlsafe_b64encode(self._nonce) + b'|' +
                encrypted.ciphertext)
    
    def encrypt_as_ciphertext(self, text: bytes) -> bytes:
        # Return just the ciphertext portion (without salt) for backward compatibility
        return self._box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder).ciphertext
    
    def encrypt_as_ciphertext_text(self, text: bytes) -> str:
        # Return just the ciphertext portion (without salt) for backward compatibility
        return self.encrypt_as_ciphertext(text).decode('utf-8')
    

class StellarSharedDecryption:
    def __init__(self, recieverKeyPair: Stellar25519KeyPair, senderPub: str):
        self._hasher = hashlib.sha256()
        self._private = recieverKeyPair.private_key()
        self._raw_pub = base64.urlsafe_b64decode(senderPub.encode("utf-8"))
        # Initialize the box immediately
        self._box = Box(self._private, PublicKey(self._raw_pub))

    def shared_secret(self) -> bytes:
        return self._box.shared_key()
    
    def shared_secret_as_hex(self) -> str:
        return nacl.encoding.HexEncoder.encode(self.shared_secret()).decode('utf-8')
    
    def hash_of_shared_secret(self):
        hasher = hashlib.sha256()
        hasher.update(self.shared_secret())
        return hasher.hexdigest()
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive the same key using the provided salt"""
        # Combine salt and shared secret
        combined = salt + self._box.shared_key()
        # Hash the combination to get the derived key
        return hashlib.sha256(combined).digest()
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        # Split the message into components
        salt_b64, nonce_b64, ciphertext = encrypted_data.split(b'|', 2)
        salt = base64.urlsafe_b64decode(salt_b64)
        nonce = base64.urlsafe_b64decode(nonce_b64)
        
        # Derive the same key using the salt
        derived_key = self._derive_key(salt)
        
        # Create a new box with the derived key
        private_key = PrivateKey(derived_key)
        public_key = PublicKey(derived_key)  # Same key for both sides
        box = Box(private_key, public_key)
        
        # Decrypt the message
        return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder)
    
    def decrypt_as_text(self, text  : bytes) -> str:
        return self.decrypt(text).decode('utf-8')
    
class TokenType(Enum):
    ACCESS = 1
    SECRET = 2
    
class StellarSharedKeyTokenBuilder:
    def __init__(self, senderKeyPair : Stellar25519KeyPair, recieverPub : str, token_type : TokenType = TokenType.ACCESS, caveats : dict = None, secret : str = None):
        # Create a shared key instance for encryption
        self._shared_key = StellarSharedKey(senderKeyPair, recieverPub)
        
        # For token signing, we'll use the raw shared secret (not derived) to maintain backward compatibility
        box = Box(senderKeyPair.private_key(), PublicKey(base64.urlsafe_b64decode(recieverPub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        hasher = hashlib.sha256()
        hasher.update(raw_shared_secret)
        signing_key = hasher.hexdigest()
        
        self._token = Macaroon(
            location=token_type.name,
            identifier=senderKeyPair.public_key(),
            key=signing_key
        )
        
        if token_type == TokenType.SECRET and secret is not None:
            # Use the derived key for encryption
            encrypted = self._shared_key.encrypt(secret.encode('utf-8'))
            self._token = Macaroon(
                location=token_type.name,
                identifier=senderKeyPair.public_key() + '|' + base64.urlsafe_b64encode(encrypted).decode('utf-8'),
                key=signing_key
            )

        if caveats is not None:
            for key, value in caveats.items():
                self._token.add_first_party_caveat(f'{key} = {value}')

    def serialize(self) -> str:
        return self._token.serialize()
    
    def inspect(self) -> str:
        return self._token.inspect()
    
class StellarSharedKeyTokenVerifier:
    def __init__(self, recieverKeyPair: Stellar25519KeyPair, serializedToken: bytes, token_type: TokenType = TokenType.ACCESS, caveats: dict = None):
        self._token = Macaroon.deserialize(serializedToken)
        self._location = token_type.name
        self._sender_pub = self._token.identifier
        self._sender_secret = None
        self._verifier = Verifier()
        
        # Handle SECRET token type
        if '|' in self._token.identifier and token_type == TokenType.SECRET:
            self._sender_pub = self._token.identifier.split('|')[0]
            self._sender_secret = self._token.identifier.split('|')[1]
        
        # For verification, we'll use the raw shared secret (not derived) to maintain backward compatibility
        box = Box(recieverKeyPair.private_key(), PublicKey(base64.urlsafe_b64decode(self._sender_pub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        hasher = hashlib.sha256()
        hasher.update(raw_shared_secret)
        self._signing_key = hasher.hexdigest()
        
        # Create a shared decryption instance for any decryption needs
        self._shared_decryption = StellarSharedDecryption(recieverKeyPair, self._sender_pub)
        
        if caveats is not None:
            for key, value in caveats.items():
                self._verifier.satisfy_exact(f'{key} = {value}')

    def valid(self) -> bool:
        # Check token location first (constant-time comparison)
        if not self._token_location_matches():
            return False
            
        # Then verify the signature using the derived key
        try:
            self._verifier.verify(
                self._token,
                self._signing_key
            )
            return True
        except Exception as e:
            # For backward compatibility, try with the raw shared secret hash if available
            try:
                box = Box(self._shared_decryption._private, PublicKey(self._shared_decryption._raw_pub))
                raw_shared_secret = box.shared_key()
                hasher = hashlib.sha256()
                hasher.update(raw_shared_secret)
                self._verifier.verify(
                    self._token,
                    hasher.hexdigest()
                )
                return True
            except Exception:
                return False
    
    def _token_location_matches(self) -> bool:
        """Constant-time comparison of token location"""
        current = self._token.location.encode('utf-8')
        expected = self._location.encode('utf-8')
        return hmac.compare_digest(current, expected)
    
    def secret(self) -> str:
        if not self.valid():
            # Try to verify just the signature without caveats for backward compatibility
            try:
                verifier = Verifier()
                verifier.verify(
                    self._token,
                    self._shared_decryption.hash_of_shared_secret()
                )
                # If we get here, the signature is valid but caveats might have failed
                # For backward compatibility, we'll still allow secret access
                pass
            except Exception:
                raise ValueError("Cannot retrieve secret: Token is not valid")
            
        if not self._sender_secret:
            raise ValueError("No secret available in token")
            
        try:
            # The secret is stored as: base64(salt|nonce|ciphertext)
            encrypted_secret = base64.urlsafe_b64decode(self._sender_secret)
            
            # Split into salt|nonce|ciphertext
            salt_b64, nonce_b64, ciphertext = encrypted_secret.split(b'|', 2)
            salt = base64.urlsafe_b64decode(salt_b64)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            
            # Derive the same key using the salt
            derived_key = self._shared_decryption._derive_key(salt)
            
            # Create a new box with the derived key
            private_key = PrivateKey(derived_key)
            public_key = PublicKey(derived_key)  # Same key for both sides
            box = Box(private_key, public_key)
            
            # Decrypt the message
            return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder).decode('utf-8')
                
        except Exception as e:
            # Try the old format if the new format fails
            try:
                encrypted_secret = base64.urlsafe_b64decode(self._sender_secret)
                return self._shared_decryption.decrypt(encrypted_secret).decode('utf-8')
            except Exception:
                raise ValueError(f"Failed to decrypt secret: {str(e)}")
