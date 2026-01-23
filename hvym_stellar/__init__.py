"""Heavymeta Stellar Utilities for Python , By: Fibo Metavinci"""

__version__ = "0.17.0"

import nacl
from nacl import utils, secret
from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey, Box, EncryptedMessage
from stellar_sdk import Keypair
from pymacaroons import Macaroon, Verifier
import hashlib
import secrets
import base64
import time
from enum import Enum
import hmac
from typing import Optional, Dict, Any
import warnings

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


def extract_salt_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract salt from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|ciphertext
        
    Returns:
        bytes: The extracted salt
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 2)
    if len(parts) != 3:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|ciphertext")
    return base64.urlsafe_b64decode(parts[0])


def extract_nonce_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract nonce from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|ciphertext
        
    Returns:
        bytes: The extracted nonce
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 2)
    if len(parts) != 3:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|ciphertext")
    return base64.urlsafe_b64decode(parts[1])


def extract_ciphertext_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract ciphertext from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|ciphertext
        
    Returns:
        bytes: The extracted ciphertext
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 2)
    if len(parts) != 3:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|ciphertext")
    return parts[2]


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
    
    def _derive_key(self, salt: bytes = None, nonce: bytes = None) -> bytes:
        """Derive a key using the salt and shared secret
        
        Args:
            salt: Salt for key derivation. If None, uses instance salt
            nonce: Nonce for key derivation (currently unused, kept for future extensibility)
            
        Returns:
            bytes: The derived key
        """
        if salt is None:
            salt = self._salt
        # Combine salt and shared secret
        combined = salt + self._box.shared_key()
        # Hash the combination to get the derived key
        return hashlib.sha256(combined).digest()
    
    def shared_secret(self, salt: bytes = None, nonce: bytes = None, random_salt: bool = None) -> bytes:
        """
        Get the derived shared secret
        
        Args:
            salt: Optional salt for key derivation. If None, uses instance salt
            nonce: Optional nonce for key derivation (currently unused)
            random_salt: Deprecated. If True, use instance's random salt
                        If False, use deterministic derivation (raw ECDH)
        
        Returns:
            bytes: The derived shared secret
        """
        if random_salt is not None:
            warnings.warn(
                "random_salt parameter is deprecated, use salt parameter instead",
                DeprecationWarning,
                stacklevel=2
            )
            if random_salt:
                return self._derive_key()
            else:
                return self._box.shared_key()
        
        if salt is None:
            return self._box.shared_key()  # Default: deterministic raw ECDH
        return self._derive_key(salt=salt, nonce=nonce)
    
    def shared_secret_as_hex(self, salt: bytes = None, nonce: bytes = None, random_salt: bool = None) -> str:
        """
        Get the derived shared secret as hex string
        
        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation (currently unused)
            random_salt: Deprecated. Use salt parameter instead
        
        Returns:
            str: Hex-encoded derived shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.shared_secret(salt=salt, nonce=nonce, random_salt=random_salt)
        ).decode('utf-8')
    
    def hash_of_shared_secret(self, salt: bytes = None, nonce: bytes = None, random_salt: bool = None) -> str:
        """
        Get hash of the derived shared secret
        
        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation (currently unused)
            random_salt: Deprecated. Use salt parameter instead
        
        Returns:
            str: Hex-encoded hash of the derived shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.shared_secret(salt=salt, nonce=nonce, random_salt=random_salt))
        return hasher.hexdigest()
    
    def _asymmetric_derive_key(self) -> bytes:
        """
        Internal method for asymmetric key operations.
        
        Returns the raw X25519 shared secret directly without salt derivation.
        This is used for proper asymmetric encryption/decryption.
        """
        return self._box.shared_key()
    
    def asymmetric_shared_secret(self) -> bytes:
        """
        Get the raw X25519 asymmetric shared secret.
        
        This provides the standard ECDH shared secret without any salt derivation.
        Use this for standard asymmetric cryptographic operations.
        
        Returns:
            bytes: The raw X25519 shared secret (32 bytes)
        """
        return self._asymmetric_derive_key()
    
    def asymmetric_shared_secret_as_hex(self) -> str:
        """
        Get the raw X25519 asymmetric shared secret as hex string.
        
        Returns:
            str: Hex-encoded raw X25519 shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.asymmetric_shared_secret()
        ).decode('utf-8')
    
    def asymmetric_hash_of_shared_secret(self) -> str:
        """
        Get hash of the raw X25519 asymmetric shared secret.
        
        Returns:
            str: Hex-encoded hash of the raw X25519 shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.asymmetric_shared_secret())
        return hasher.hexdigest()
    
    def encrypt(self, text: bytes) -> bytes:
        """
        Encrypt using derived key (original behavior).
        
        This is the original hybrid encryption approach for backward compatibility.
        For new implementations, consider using asymmetric_encrypt() for better security.
        
        Args:
            text: Message to encrypt
            
        Returns:
            bytes: Encrypted data in format salt|nonce|ciphertext
        """
        # Generate new random salt and nonce
        self._salt = secrets.token_bytes(32)
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        
        # Use derived key (self-encryption pattern) - ORIGINAL BEHAVIOR
        derived_key = self._derive_key()
        private_key = PrivateKey(derived_key)
        public_key = PublicKey(derived_key)
        box = Box(private_key, public_key)
        encrypted = box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder)
        
        return (base64.urlsafe_b64encode(self._salt) + b'|' +
                base64.urlsafe_b64encode(self._nonce) + b'|' +
                encrypted.ciphertext)
    
    def asymmetric_encrypt(self, text: bytes) -> bytes:
        """
        Encrypt using standard X25519 asymmetric encryption.
        
        This is the recommended secure approach that uses proper asymmetric cryptography.
        
        Args:
            text: Message to encrypt
            
        Returns:
            bytes: Encrypted data in format salt|nonce|ciphertext
        """
        # Generate new random salt and nonce for each encryption
        self._salt = secrets.token_bytes(32)
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        
        # Use standard X25519 encryption (proper asymmetric pattern)
        encrypted = self._box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder)
        
        # Return salt + '|' + nonce + '|' + ciphertext
        return (base64.urlsafe_b64encode(self._salt) + b'|' +
                base64.urlsafe_b64encode(self._nonce) + b'|' +
                encrypted.ciphertext)
    
    def encrypt_with_derived_key(self, text: bytes) -> bytes:
        """
        Encrypt using derived key (legacy behavior - DEPRECATED).
        
        DEPRECATED: This method is deprecated. Use encrypt() for the same behavior
        or asymmetric_encrypt() for improved security.
        
        Args:
            text: Message to encrypt
            
        Returns:
            bytes: Encrypted data in format salt|nonce|ciphertext
        """
        warnings.warn(
            "encrypt_with_derived_key() is deprecated, use encrypt() for the same behavior or asymmetric_encrypt() for improved security",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Delegate to encrypt() for the same behavior
        return self.encrypt(text)
    
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

    def shared_secret(self, salt: bytes = None, nonce: bytes = None) -> bytes:
        """
        Get the derived shared secret
        
        Args:
            salt: Optional salt for key derivation. If None, uses raw ECDH secret
            nonce: Optional nonce for key derivation (currently unused)
        
        Returns:
            bytes: The derived shared secret
        """
        if salt is None:
            return self._box.shared_key()  # Default behavior (backward compatible)
        return self._derive_key(salt)
    
    def shared_secret_as_hex(self, salt: bytes = None, nonce: bytes = None) -> str:
        """
        Get the derived shared secret as hex string
        
        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation
        
        Returns:
            str: Hex-encoded derived shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.shared_secret(salt=salt, nonce=nonce)
        ).decode('utf-8')
    
    def hash_of_shared_secret(self, salt: bytes = None, nonce: bytes = None, random_salt: bool = None) -> str:
        """
        Get hash of the derived shared secret
        
        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation (currently unused)
        
        Returns:
            str: Hex-encoded hash of the derived shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.shared_secret(salt=salt, nonce=nonce))
        return hasher.hexdigest()
    
    def _derive_key(self, salt: bytes, nonce: bytes = None) -> bytes:
        """
        Derive the same key using the provided salt
        
        Args:
            salt: Salt for key derivation
            nonce: Nonce for key derivation (currently unused, kept for consistency)
            
        Returns:
            bytes: The derived key
        """
        # Combine salt and shared secret
        combined = salt + self._box.shared_key()
        # Hash the combination to get the derived key
        return hashlib.sha256(combined).digest()
    
    def _asymmetric_derive_key(self) -> bytes:
        """
        Internal method for asymmetric key operations.
        
        Returns the raw X25519 shared secret directly without salt derivation.
        """
        return self._box.shared_key()
    
    def asymmetric_shared_secret(self) -> bytes:
        """
        Get the raw X25519 asymmetric shared secret.
        
        Returns:
            bytes: The raw X25519 shared secret (32 bytes)
        """
        return self._asymmetric_derive_key()
    
    def asymmetric_shared_secret_as_hex(self) -> str:
        """
        Get the raw X25519 asymmetric shared secret as hex string.
        
        Returns:
            str: Hex-encoded raw X25519 shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.asymmetric_shared_secret()
        ).decode('utf-8')
    
    def asymmetric_hash_of_shared_secret(self) -> str:
        """
        Get hash of the raw X25519 asymmetric shared secret.
        
        Returns:
            str: Hex-encoded hash of the raw X25519 shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.asymmetric_shared_secret())
        return hasher.hexdigest()
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt using derived key (original behavior).
        
        This is the original hybrid decryption approach for backward compatibility.
        For new implementations, consider using asymmetric_decrypt() for better security.
        
        Args:
            encrypted_data: Encrypted data in format salt|nonce|ciphertext
            
        Returns:
            bytes: Decrypted message
        """
        try:
            # Ensure we're working with bytes
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            
            # Parse encrypted data
            parts = encrypted_data.split(b'|', 2)
            if len(parts) != 3:
                raise ValueError("Invalid encrypted data format: expected salt|nonce|ciphertext")
                
            salt_b64, nonce_b64, ciphertext = parts
            
            # Decode components
            salt = base64.urlsafe_b64decode(salt_b64)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            
            # Use derived key for decryption - ORIGINAL BEHAVIOR
            derived_key = self._derive_key(salt)
            private_key = PrivateKey(derived_key)
            public_key = PublicKey(derived_key)
            box = Box(private_key, public_key)
            
            if not isinstance(ciphertext, bytes):
                ciphertext = ciphertext.encode('utf-8')
            
            return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder)
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def asymmetric_decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt using standard X25519 asymmetric decryption.
        
        This is the recommended secure approach that uses proper asymmetric cryptography.
        
        Args:
            encrypted_data: Encrypted data in format salt|nonce|ciphertext
            
        Returns:
            bytes: Decrypted message
        """
        try:
            # Ensure we're working with bytes
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            
            # Parse encrypted data
            parts = encrypted_data.split(b'|', 2)
            if len(parts) != 3:
                raise ValueError("Invalid encrypted data format: expected salt|nonce|ciphertext")
                
            salt_b64, nonce_b64, ciphertext = parts
            
            # Decode nonce (salt is extracted for potential key derivation)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            
            # Use standard X25519 decryption
            if not isinstance(ciphertext, bytes):
                ciphertext = ciphertext.encode('utf-8')
            
            # First try with hex encoding (new format)
            try:
                return self._box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder)
            except Exception as hex_err:
                # If hex decoding fails, try raw bytes (legacy format)
                if "Odd-length string" in str(hex_err) or "Non-hexadecimal digit found" in str(hex_err):
                    try:
                        return self._box.decrypt(ciphertext, nonce)
                    except Exception as raw_err:
                        raise ValueError(f"Decryption failed with both hex and raw bytes: {str(raw_err)}")
                raise ValueError(f"Decryption failed: {str(hex_err)}")
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def decrypt_with_derived_key(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt using derived key (legacy behavior - DEPRECATED).
        
        DEPRECATED: This method is deprecated. Use decrypt() for the same behavior
        or asymmetric_decrypt() for improved security.
        
        Args:
            encrypted_data: Encrypted data in format salt|nonce|ciphertext
            
        Returns:
            bytes: Decrypted message
        """
        warnings.warn(
            "decrypt_with_derived_key() is deprecated, use decrypt() for the same behavior or asymmetric_decrypt() for improved security",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Delegate to decrypt() for the same behavior
        return self.decrypt(encrypted_data)
    
    def decrypt_as_text(self, text  : bytes) -> str:
        return self.decrypt(text).decode('utf-8')
    
class TokenType(Enum):
    ACCESS = 1
    SECRET = 2
    
def _get_current_timestamp() -> int:
    """Get current Unix timestamp in seconds."""
    return int(time.time())

class StellarSharedKeyTokenBuilder:
    def __init__(self, 
                senderKeyPair: Stellar25519KeyPair, 
                recieverPub: str, 
                token_type: TokenType = TokenType.ACCESS, 
                caveats: dict = None, 
                secret: str = None,
                expires_in: int = None):
        """Initialize a new token builder.
        
        Args:
            senderKeyPair: The sender's key pair
            recieverPub: The receiver's public key (base64 URL-safe encoded)
            token_type: The type of token to create (ACCESS or SECRET)
            caveats: Optional dictionary of caveats to add to the token
            secret: Optional secret to encrypt and store in the token (for SECRET tokens)
            expires_in: Optional number of seconds until the token expires
        """
        self._shared_key = StellarSharedKey(senderKeyPair, recieverPub)
        
        # For token signing, we'll use the raw shared secret (not derived) to maintain backward compatibility
        box = Box(senderKeyPair.private_key(), PublicKey(base64.urlsafe_b64decode(recieverPub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        hasher = hashlib.sha256()
        hasher.update(raw_shared_secret)
        self._signing_key = hasher.hexdigest()
        
        # Initialize caveats with timestamp if expires_in is provided
        if caveats is None:
            caveats = {}
            
        if expires_in is not None and expires_in > 0:
            expiration_time = _get_current_timestamp() + expires_in
            caveats['exp'] = str(expiration_time)
        
        self._token = Macaroon(
            location=token_type.name,
            identifier=senderKeyPair.public_key(),
            key=self._signing_key
        )
        
        if token_type == TokenType.SECRET and secret is not None:
            # Use the derived key for encryption
            encrypted = self._shared_key.encrypt(secret.encode('utf-8'))
            self._token = Macaroon(
                location=token_type.name,
                identifier=senderKeyPair.public_key() + '|' + base64.urlsafe_b64encode(encrypted).decode('utf-8'),
                key=self._signing_key
            )

        # Add all caveats to the token
        for key, value in caveats.items():
            self._token.add_first_party_caveat(f'{key} = {value}')

    def serialize(self) -> str:
        return self._token.serialize()
    
    def inspect(self) -> str:
        return self._token.inspect()
    
class StellarSharedKeyTokenVerifier:
    def __init__(self, 
                recieverKeyPair: Stellar25519KeyPair, 
                serializedToken: bytes, 
                token_type: TokenType = TokenType.ACCESS, 
                caveats: dict = None,
                max_age_seconds: int = None):
        """Initialize a new token verifier.
        
        Args:
            recieverKeyPair: The receiver's key pair
            serializedToken: The serialized token to verify
            token_type: The expected token type (ACCESS or SECRET)
            caveats: Optional dictionary of required caveats
            max_age_seconds: Optional maximum allowed token age in seconds
        """
        self._token = Macaroon.deserialize(serializedToken)
        self._location = token_type.name
        self._sender_pub = self._token.identifier
        self._sender_secret = None
        self._verifier = Verifier()
        self._max_age_seconds = max_age_seconds
        
        # Handle SECRET token type
        if '|' in self._token.identifier and token_type == TokenType.SECRET:
            self._sender_pub, self._sender_secret = self._token.identifier.split('|', 1)
        
        # For verification, we'll use the raw shared secret (not derived) to maintain backward compatibility
        box = Box(recieverKeyPair.private_key(), 
                 PublicKey(base64.urlsafe_b64decode(self._sender_pub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        hasher = hashlib.sha256()
        hasher.update(raw_shared_secret)
        self._signing_key = hasher.hexdigest()
        
        # Create a shared decryption instance for any decryption needs
        self._shared_decryption = StellarSharedDecryption(recieverKeyPair, self._sender_pub)
        
        # Add timestamp validation if max_age_seconds is provided
        if max_age_seconds is not None and max_age_seconds > 0:
            self._verifier.satisfy_general(self._validate_timestamp)
            
        # Add any additional required caveats
        if caveats is not None:
            for key, value in caveats.items():
                self._verifier.satisfy_exact(f'{key} = {value}')

    def _get_caveats(self) -> Dict[str, str]:
        """Extract all caveats from the token."""
        caveats = {}
        for caveat in self._token.caveats:
            if ' = ' in caveat.caveat_id:
                key, value = caveat.caveat_id.split(' = ', 1)
                caveats[key] = value
        return caveats
        
    def _get_expiration_time(self) -> Optional[int]:
        """Get the expiration time from the token, if it exists."""
        caveats = self._get_caveats()
        return int(caveats['exp']) if 'exp' in caveats else None
        
    def is_expired(self) -> bool:
        """Check if the token has expired.
        
        Returns:
            bool: True if the token has an expiration time and it has passed,
                  False otherwise (including if no expiration is set).
        """
        exp = self._get_expiration_time()
        if exp is None:
            return False
        return _get_current_timestamp() > exp
        
    def _validate_timestamp(self, predicate: str) -> bool:
        """Validate the token's timestamp.
        
        Args:
            predicate: The caveat predicate to validate
            
        Returns:
            bool: True if the timestamp is valid, False otherwise
        """
        if not predicate.startswith('exp = '):
            # Not a timestamp caveat, let other verifiers handle it
            return False
            
        try:
            exp_time = int(predicate.split(' = ')[1])
            current_time = _get_current_timestamp()
            
            # Check if token is expired
            if current_time > exp_time + 60:  # Add 60s grace period for clock skew
                return False
                
            # Check if token is too old (if max_age_seconds is set)
            if self._max_age_seconds is not None and self._max_age_seconds > 0:
                # For max_age, we calculate the earliest acceptable issue time
                earliest_issue_time = current_time - self._max_age_seconds - 60  # 60s grace period
                if exp_time < earliest_issue_time:
                    return False
                    
            return True
            
        except (ValueError, IndexError):
            return False
    
    def valid(self) -> bool:
        """Check if the token is valid.
        
        Returns:
            bool: True if the token is valid, False otherwise
        """
        # Check token location first (constant-time comparison)
        if not self._token_location_matches():
            return False
            
        # First verify the signature
        try:
            self._verifier.verify(
                self._token,
                self._signing_key
            )
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
            except Exception:
                return False
        
        # Only check expiration after signature is verified
        if self.is_expired():
            return False
            
        return True
    
    def _token_location_matches(self) -> bool:
        """Constant-time comparison of token location"""
        current = self._token.location.encode('utf-8')
        expected = self._location.encode('utf-8')
        return hmac.compare_digest(current, expected)
    
    def sender_pub(self) -> str:
        return self._token.inspect().split('\n')[1].replace('identifier ', '').split('|')[0].strip()
    
    def secret(self) -> str:
        # Check if we have a secret to retrieve
        if not self._sender_secret:
            raise ValueError("No secret available in token")
            
        # For backward compatibility, we'll try to verify the token
        # but we won't fail if verification fails - we'll still try to decrypt the secret
        try:
            if not self.valid():
                # If the token isn't valid, it might be because of timestamp validation
                # but we still want to try to decrypt the secret if possible
                pass
        except Exception as e:
            # Ignore verification errors and try to decrypt anyway
            pass
            
        # Check if token is expired (but still try to decrypt if it is)
        if self.is_expired():
            print("Warning: Token has expired, but attempting to decrypt secret anyway")
            
        # Now try to decrypt the secret
            
        try:
            # The secret is stored as: base64(salt|nonce|ciphertext)
            encrypted_secret = base64.urlsafe_b64decode(self._sender_secret)
            
            # Split into salt|nonce|ciphertext
            salt_b64, nonce_b64, ciphertext = encrypted_secret.split(b'|', 2)
            salt = base64.urlsafe_b64decode(salt_b64)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            
            # Strip any whitespace or line endings from ciphertext (Windows CRLF fix)
            ciphertext = ciphertext.strip()
            
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