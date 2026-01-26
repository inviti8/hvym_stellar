"""Heavymeta Stellar Utilities for Python , By: Fibo Metavinci"""

__version__ = "0.19.0"

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
import os
import json
from enum import Enum
import hmac
from typing import Optional, Dict, Any
import warnings


class DomainSeparation:
    """Constants for cryptographic domain separation.

    Domain separation ensures that keys derived for different purposes
    are cryptographically independent, preventing cross-protocol attacks.
    """
    # Version prefix for future-proofing
    VERSION = b"hvym_v1"

    # Token domains
    TOKEN_SIGNING = VERSION + b":token:sign"
    TOKEN_SECRET = VERSION + b":token:secret"

    # Encryption domains
    HYBRID_ENCRYPT = VERSION + b":hybrid:encrypt"
    ASYMMETRIC_ENCRYPT = VERSION + b":asymmetric:encrypt"

    # Data token domains
    DATA_FILE = VERSION + b":data:file"


def _derive_signing_key(shared_secret: bytes, domain: bytes = DomainSeparation.TOKEN_SIGNING) -> str:
    """Derive a signing key from shared secret with domain separation.

    Args:
        shared_secret: The raw ECDH shared secret
        domain: Domain separation constant (default: TOKEN_SIGNING)

    Returns:
        str: Hex-encoded signing key
    """
    hasher = hashlib.sha256()
    hasher.update(domain + shared_secret)
    return hasher.hexdigest()


class StellarKeyBase:
    """Base class for Stellar shared key operations.

    Provides common key derivation and shared secret methods used by
    both StellarSharedKey (encryption) and StellarSharedDecryption (decryption).
    """

    def __init__(self, private_key: PrivateKey, public_key_raw: bytes):
        """Initialize base key operations.

        Args:
            private_key: The local party's X25519 private key
            public_key_raw: The remote party's raw public key bytes
        """
        self._box = Box(private_key, PublicKey(public_key_raw))
        self._salt = secrets.token_bytes(32)

    def _derive_key(self, salt: bytes = None, nonce: bytes = None) -> bytes:
        """Derive a key using the salt and shared secret.

        Args:
            salt: Salt for key derivation. If None, uses instance salt
            nonce: Nonce for key derivation (currently unused, kept for extensibility)

        Returns:
            bytes: The derived key
        """
        if salt is None:
            salt = self._salt
        # Combine salt and shared secret
        combined = salt + self._box.shared_key()
        # Hash the combination to get the derived key
        return hashlib.sha256(combined).digest()

    def shared_secret(self, salt: bytes = None, nonce: bytes = None) -> bytes:
        """Get the derived shared secret.

        Args:
            salt: Optional salt for key derivation. If None, returns raw ECDH secret
            nonce: Optional nonce for key derivation (currently unused)

        Returns:
            bytes: The derived shared secret
        """
        if salt is None:
            return self._box.shared_key()  # Default: raw ECDH
        return self._derive_key(salt=salt, nonce=nonce)

    def shared_secret_as_hex(self, salt: bytes = None, nonce: bytes = None) -> str:
        """Get the derived shared secret as hex string.

        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation (currently unused)

        Returns:
            str: Hex-encoded derived shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.shared_secret(salt=salt, nonce=nonce)
        ).decode('utf-8')

    def hash_of_shared_secret(self, salt: bytes = None, nonce: bytes = None) -> str:
        """Get hash of the derived shared secret.

        Args:
            salt: Optional salt for key derivation
            nonce: Optional nonce for key derivation (currently unused)

        Returns:
            str: Hex-encoded hash of the derived shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.shared_secret(salt=salt, nonce=nonce))
        return hasher.hexdigest()

    def _asymmetric_derive_key(self) -> bytes:
        """Internal method for asymmetric key operations.

        Returns the raw X25519 shared secret directly without salt derivation.
        """
        return self._box.shared_key()

    def asymmetric_shared_secret(self) -> bytes:
        """Get the raw X25519 asymmetric shared secret.

        Returns:
            bytes: The raw X25519 shared secret (32 bytes)
        """
        return self._asymmetric_derive_key()

    def asymmetric_shared_secret_as_hex(self) -> str:
        """Get the raw X25519 asymmetric shared secret as hex string.

        Returns:
            str: Hex-encoded raw X25519 shared secret
        """
        return nacl.encoding.HexEncoder.encode(
            self.asymmetric_shared_secret()
        ).decode('utf-8')

    def asymmetric_hash_of_shared_secret(self) -> str:
        """Get hash of the raw X25519 asymmetric shared secret.

        Returns:
            str: Hex-encoded hash of the raw X25519 shared secret
        """
        hasher = hashlib.sha256()
        hasher.update(self.asymmetric_shared_secret())
        return hasher.hexdigest()


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
        encrypted_data: The encrypted data in format salt|nonce|signature|ciphertext
        
    Returns:
        bytes: The extracted salt
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 3)
    if len(parts) != 4:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|signature|ciphertext")
    return base64.urlsafe_b64decode(parts[0])


def extract_nonce_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract nonce from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|signature|ciphertext
        
    Returns:
        bytes: The extracted nonce
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 3)
    if len(parts) != 4:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|signature|ciphertext")
    return base64.urlsafe_b64decode(parts[1])


def extract_signature_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract signature from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|signature|ciphertext
        
    Returns:
        bytes: The extracted signature
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 3)
    if len(parts) != 4:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|signature|ciphertext")
    return base64.urlsafe_b64decode(parts[2])


def extract_ciphertext_from_encrypted(encrypted_data: bytes) -> bytes:
    """
    Extract ciphertext from encrypted data returned by encrypt()
    
    Args:
        encrypted_data: The encrypted data in format salt|nonce|signature|ciphertext
        
    Returns:
        bytes: The extracted ciphertext
        
    Raises:
        ValueError: If encrypted data format is invalid
    """
    parts = encrypted_data.split(b'|', 3)
    if len(parts) != 4:
        raise ValueError("Invalid encrypted data format: expected salt|nonce|signature|ciphertext")
    return parts[3]


class StellarSharedKey(StellarKeyBase):
    """Encryption operations using Stellar keypairs."""

    def __init__(self, senderKeyPair: Stellar25519KeyPair, receiverPub: str):
        """
        Initialize shared key for encryption.

        Args:
            senderKeyPair: The sender's key pair
            receiverPub: The receiver's public key (base64 URL-safe encoded)
        """

        # Decode receiver public key
        raw_pub = base64.urlsafe_b64decode(receiverPub.encode("utf-8"))

        # Initialize base class with key exchange
        super().__init__(senderKeyPair.private_key(), raw_pub)

        # Additional encryption-specific state
        self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
        self._signing_key = senderKeyPair.signing_key()  # Store sender's signing key

    def nonce(self) -> bytes:
        return nacl.encoding.HexEncoder.encode(self._nonce).decode('utf-8')

    # Note: _derive_key() is inherited from StellarKeyBase

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

    # Note: asymmetric methods are inherited from StellarKeyBase

    def encrypt(self, text: bytes) -> bytes:
        """
        Encrypt using signature-based hybrid approach.
        
        This version uses the sender's Ed25519 signing key for authenticity,
        providing true cryptographic authentication.
        
        Args:
            text: Message to encrypt
            
        Returns:
            bytes: Encrypted data in format salt|nonce|signature|ciphertext
        """
        try:
            # Generate fresh salt/nonce
            self._salt = secrets.token_bytes(32)
            self._nonce = secrets.token_bytes(secret.SecretBox.NONCE_SIZE)
            
            # Derive base key using salted SHA-256
            derived_key = self._derive_key()
            
            # Use sender's existing signing key for authenticity
            # Sign salt + nonce with sender's actual Ed25519 key
            message = self._salt + self._nonce
            signature = self._signing_key.sign(message).signature  # 64 bytes Ed25519 sig
            
            # Derive differentiated private/public bytes using signature parts
            # This creates cryptographically strong key material from the signature
            private_bytes = hashlib.sha256(derived_key + signature[:32]).digest()
            public_bytes = hashlib.sha256(derived_key + signature[32:]).digest()

            # Build the Box with derived keys
            private_key = PrivateKey(private_bytes)
            public_key = PublicKey(public_bytes)
            box = Box(private_key, public_key)
            
            # Encrypt using hex encoder for consistency
            encrypted = box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder)
            
            # Return format: salt|nonce|signature|ciphertext
            return (base64.urlsafe_b64encode(self._salt) + b'|' +
                    base64.urlsafe_b64encode(self._nonce) + b'|' +
                    base64.urlsafe_b64encode(signature) + b'|' +
                    encrypted.ciphertext)
                    
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
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
    
    def encrypt_as_ciphertext(self, text: bytes) -> bytes:
        # Return just the ciphertext portion (without salt) for backward compatibility
        return self._box.encrypt(text, self._nonce, encoder=nacl.encoding.HexEncoder).ciphertext
    
    def encrypt_as_ciphertext_text(self, text: bytes) -> str:
        # Return just the ciphertext portion (without salt) for backward compatibility
        return self.encrypt_as_ciphertext(text).decode('utf-8')
    

class StellarSharedDecryption(StellarKeyBase):
    """Decryption operations using Stellar keypairs."""

    def __init__(self, receiverKeyPair: Stellar25519KeyPair, senderPub: str):
        """
        Initialize shared decryption.

        Args:
            receiverKeyPair: The receiver's key pair
            senderPub: The sender's public key (base64 URL-safe encoded)
        """

        # Decode sender public key and initialize base class
        raw_pub = base64.urlsafe_b64decode(senderPub.encode("utf-8"))
        super().__init__(receiverKeyPair.private_key(), raw_pub)

    # Note: shared_secret, shared_secret_as_hex, hash_of_shared_secret,
    # _derive_key, and asymmetric methods are inherited from StellarKeyBase

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
                else:
                    raise ValueError(f"Decryption failed: {str(hex_err)}")
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: bytes, from_address: str) -> bytes:
        """
        Decrypt using signature-based hybrid approach.

        Args:
            encrypted_data: Encrypted data in format salt|nonce|signature|ciphertext
            from_address: Stellar public key address for signature verification (REQUIRED)

        Returns:
            bytes: Decrypted message

        Raises:
            ValueError: If from_address is not provided, signature verification fails,
                       or decryption fails
        """
        if from_address is None:
            raise ValueError(
                "from_address is required for signature verification. "
                "This ensures sender authenticity and prevents impersonation attacks."
            )

        try:
            # Ensure we're working with bytes
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')

            # Parse signature-based format: salt|nonce|signature|ciphertext
            parts = encrypted_data.split(b'|', 3)
            if len(parts) != 4:
                raise ValueError("Invalid encrypted data format: expected salt|nonce|signature|ciphertext")

            salt_b64, nonce_b64, signature_b64, ciphertext = parts

            # Decode components
            salt = base64.urlsafe_b64decode(salt_b64)
            nonce = base64.urlsafe_b64decode(nonce_b64)
            signature = base64.urlsafe_b64decode(signature_b64)

            # Derive base key
            derived_key = self._derive_key(salt)

            # Always verify signature for sender authenticity
            sender_keypair = Keypair.from_public_key(from_address)
            sender_verify_key = sender_keypair.verify_key

            # Verify the signature of salt + nonce
            message_to_verify = salt + nonce
            try:
                sender_verify_key.verify(message_to_verify, signature)
            except Exception as e:
                raise ValueError(f"Signature verification failed: {str(e)}")

            # Derive private/public bytes using signature parts
            private_bytes = hashlib.sha256(derived_key + signature[:32]).digest()
            public_bytes = hashlib.sha256(derived_key + signature[32:]).digest()

            private_key = PrivateKey(private_bytes)
            public_key = PublicKey(public_bytes)
            box = Box(private_key, public_key)

            if not isinstance(ciphertext, bytes):
                ciphertext = ciphertext.encode('utf-8')
            ciphertext = ciphertext.strip()

            return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder)

        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def decrypt_as_text(self, encrypted_data: bytes, from_address: str) -> str:
        """
        Decrypt and return as UTF-8 text.

        Args:
            encrypted_data: Encrypted data in format salt|nonce|signature|ciphertext
            from_address: Stellar public key address for signature verification (REQUIRED)

        Returns:
            str: Decrypted message as UTF-8 string
        """
        return self.decrypt(encrypted_data, from_address).decode('utf-8')

# ... (rest of the code remains the same)

class TokenType(Enum):
    ACCESS = 1
    SECRET = 2

    
def _get_current_timestamp() -> int:
    """Get current Unix timestamp in seconds."""
    return int(time.time())

class StellarSharedKeyTokenBuilder:
    def __init__(self,
                senderKeyPair: Stellar25519KeyPair,
                receiverPub: str,
                token_type: TokenType = TokenType.ACCESS,
                caveats: dict = None,
                secret: str = None,
                expires_in: int = None):
        """Initialize a new token builder.

        Args:
            senderKeyPair: The sender's key pair
            receiverPub: The receiver's public key (base64 URL-safe encoded)
            token_type: The type of token to create (ACCESS or SECRET)
            caveats: Optional dictionary of caveats to add to the token
            secret: Optional secret to encrypt and store in the token (for SECRET tokens)
            expires_in: Optional number of seconds until the token expires
        """
        self._shared_key = StellarSharedKey(senderKeyPair, receiverPub)

        # Derive signing key with domain separation for cryptographic independence
        box = Box(senderKeyPair.private_key(), PublicKey(base64.urlsafe_b64decode(receiverPub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        self._signing_key = _derive_signing_key(raw_shared_secret, DomainSeparation.TOKEN_SIGNING)
        
        # Initialize caveats with timestamp if expires_in is provided
        if caveats is None:
            caveats = {}
            
        if expires_in is not None:
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
        """Serialize the token with tamper-evident checksum.

        The checksum protects against base64 malleability attacks where
        different base64 strings can decode to identical bytes,
        potentially bypassing macaroon's HMAC verification.
        See: https://eprint.iacr.org/2022/361.pdf
        """
        serialized = self._token.serialize()
        checksum = hashlib.sha256(serialized.encode('utf-8')).hexdigest()[:8]
        return serialized + "|" + checksum
    
    def inspect(self) -> str:
        return self._token.inspect()
    
class StellarSharedKeyTokenVerifier:
    def __init__(self,
                receiverKeyPair: Stellar25519KeyPair,
                serializedToken: bytes,
                token_type: TokenType = TokenType.ACCESS,
                caveats: dict = None,
                max_age_seconds: int = None):
        """Initialize a new token verifier.

        Args:
            receiverKeyPair: The receiver's key pair
            serializedToken: The serialized token to verify
            token_type: The expected token type (ACCESS or SECRET)
            caveats: Optional dictionary of required caveats
            max_age_seconds: Optional maximum allowed token age in seconds
        """
        # Parse token and checksum
        if isinstance(serializedToken, str):
            token_parts = serializedToken.rsplit('|', 1)
        else:
            token_parts = serializedToken.decode('utf-8').rsplit('|', 1)
        
        if len(token_parts) != 2:
            # Invalid format - no checksum found
            raise ValueError("Invalid token format: missing checksum")

        token_data, provided_checksum = token_parts

        # Verify checksum to detect tampering
        calculated_checksum = hashlib.sha256(token_data.encode('utf-8')).hexdigest()[:8]
        if calculated_checksum != provided_checksum:
            raise ValueError("Token tampering detected: checksum mismatch")
            
        self._token = Macaroon.deserialize(token_data)
        self._location = token_type.name
        self._sender_pub = self._token.identifier
        self._sender_secret = None
        self._verifier = Verifier()
        self._max_age_seconds = max_age_seconds
        
        # Handle SECRET token type
        if '|' in self._token.identifier and token_type == TokenType.SECRET:
            self._sender_pub, self._sender_secret = self._token.identifier.split('|', 1)
        
        # Derive signing key with domain separation (must match token builder)
        box = Box(receiverKeyPair.private_key(),
                 PublicKey(base64.urlsafe_b64decode(self._sender_pub.encode("utf-8"))))
        raw_shared_secret = box.shared_key()
        self._signing_key = _derive_signing_key(raw_shared_secret, DomainSeparation.TOKEN_SIGNING)

        # Create a shared decryption instance for any decryption needs
        self._shared_decryption = StellarSharedDecryption(receiverKeyPair=receiverKeyPair, senderPub=self._sender_pub)

        # Add general satisfier for file caveats (informational, validated by app)
        self._verifier.satisfy_general(self._satisfy_file_caveats)

        # Add general satisfier for expiration caveats
        self._verifier.satisfy_general(self._satisfy_expiration)

        # Add timestamp validation if max_age_seconds is provided
        if max_age_seconds is not None and max_age_seconds > 0:
            self._verifier.satisfy_general(self._validate_timestamp)

        # Add any additional required caveats
        if caveats is not None:
            for key, value in caveats.items():
                self._verifier.satisfy_exact(f'{key} = {value}')

    def _satisfy_file_caveats(self, predicate: str) -> bool:
        """Satisfy file-related caveats (informational, validated by application)."""
        # File caveats are prefixed with 'file_' and are for application validation
        if predicate.startswith('file_'):
            return True
        return False

    def _satisfy_expiration(self, predicate: str) -> bool:
        """Satisfy expiration caveats by checking if token is not expired."""
        if not predicate.startswith('exp = '):
            return False
        try:
            exp_time = int(predicate.split(' = ')[1])
            current_time = _get_current_timestamp()
            # Token is valid if not expired (with 60s grace period for clock skew)
            return current_time <= exp_time + 60
        except (ValueError, IndexError):
            return False

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

    def _get_required_caveats(self) -> Dict[str, str]:
        """Extract required caveats from the verifier setup."""
        # This is a workaround to get the caveats that were added during initialization
        # We need to reconstruct them from the token itself
        caveats = {}
        for caveat in self._token.caveats:
            if ' = ' in caveat.caveat_id:
                key, value = caveat.caveat_id.split(' = ', 1)
                caveats[key] = value
        return caveats
                                
    def valid(self) -> bool:
        """Check if the token is valid.
        
        Returns:
            bool: True if the token is valid, False otherwise
        """
        # Check token location first (constant-time comparison)
        if not self._token_location_matches():
            return False
            
        # CRITICAL: Verify signature with proper caveat handling
        # Use the original verifier but ensure no fallback behavior
        try:
            self._verifier.verify(self._token, self._signing_key)
        except Exception:
            return False  # FAIL FAST - SIGNATURE INVALID
        
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
    
    def secret(self, validate: bool = True, allow_expired: bool = False) -> str:
        """
        Retrieve the decrypted secret from the token.

        Args:
            validate: If True (default), validates token signature before decryption.
                     Set to False only for recovery/debugging scenarios.
            allow_expired: If True, allows decryption of expired but otherwise
                          valid tokens. Defaults to False.

        Returns:
            str: The decrypted secret

        Raises:
            ValueError: If no secret available in token
            ValueError: If validate=True and token signature verification fails
            ValueError: If token is expired and allow_expired=False
            ValueError: If decryption fails
        """
        # Check if we have a secret to retrieve
        if not self._sender_secret:
            raise ValueError("No secret available in token")

        # Enforce token validation before decryption
        if validate:
            # Check token location first
            if not self._token_location_matches():
                raise ValueError("Token location mismatch - invalid token type")

            # Verify token signature
            try:
                self._verifier.verify(self._token, self._signing_key)
            except Exception as e:
                raise ValueError(f"Token signature verification failed: {e}")

        # Check expiration separately (allows for allow_expired override)
        if self.is_expired():
            if not allow_expired:
                exp_time = self._get_expiration_time()
                current_time = _get_current_timestamp()
                raise ValueError(
                    f"Token expired at {exp_time} (current time: {current_time}). "
                    f"Set allow_expired=True to decrypt anyway."
                )
            warnings.warn(
                "Decrypting secret from expired token.",
                UserWarning,
                stacklevel=2
            )

        # Now perform decryption
        try:
            # The secret is stored as: base64(salt_b64|nonce_b64|signature_b64|ciphertext_hex)
            encrypted_secret = base64.urlsafe_b64decode(self._sender_secret)

            # Split into salt|nonce|signature|ciphertext (4 parts for signature-based hybrid)
            parts = encrypted_secret.split(b'|', 3)

            if len(parts) == 4:
                # New signature-based hybrid format
                salt_b64, nonce_b64, signature_b64, ciphertext = parts
                salt = base64.urlsafe_b64decode(salt_b64)
                nonce = base64.urlsafe_b64decode(nonce_b64)
                signature = base64.urlsafe_b64decode(signature_b64)

                # Strip any whitespace or line endings from ciphertext (Windows CRLF fix)
                ciphertext = ciphertext.strip()

                # Derive base key using salt
                derived_key = self._shared_decryption._derive_key(salt)

                # Derive private/public bytes using signature parts (same as encrypt())
                private_bytes = hashlib.sha256(derived_key + signature[:32]).digest()
                public_bytes = hashlib.sha256(derived_key + signature[32:]).digest()

                # Create box with derived keys
                private_key = PrivateKey(private_bytes)
                public_key = PublicKey(public_bytes)
                box = Box(private_key, public_key)

                # Decrypt the message
                return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder).decode('utf-8')

            elif len(parts) == 3:
                # Legacy 3-part format (salt|nonce|ciphertext)
                salt_b64, nonce_b64, ciphertext = parts
                salt = base64.urlsafe_b64decode(salt_b64)
                nonce = base64.urlsafe_b64decode(nonce_b64)
                ciphertext = ciphertext.strip()

                # Derive the same key using the salt
                derived_key = self._shared_decryption._derive_key(salt)

                # Create a new box with the derived key (same key for both sides)
                private_key = PrivateKey(derived_key)
                public_key = PublicKey(derived_key)
                box = Box(private_key, public_key)

                return box.decrypt(ciphertext, nonce, encoder=nacl.encoding.HexEncoder).decode('utf-8')

            else:
                raise ValueError(f"Invalid encrypted secret format: expected 3 or 4 parts, got {len(parts)}")

        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Failed to decrypt secret: {str(e)}")


class FileCaveatVerifier:
    """Verifies file-related caveats during extraction.

    Provides real enforcement of file caveats (size, type, hash) rather than
    treating them as informational metadata only.
    """

    def __init__(self, caveats: Dict[str, str]):
        """Initialize with caveats from token.

        Args:
            caveats: Dictionary of caveat key-value pairs
        """
        self.caveats = caveats

    def verify_size(self, actual_size: int) -> bool:
        """Verify file size against max_size caveat.

        Args:
            actual_size: Actual file size in bytes

        Returns:
            bool: True if size is acceptable

        Raises:
            ValueError: If size exceeds caveat limit
        """
        if 'file_max_size' in self.caveats:
            max_size = int(self.caveats['file_max_size'])
            if actual_size > max_size:
                raise ValueError(
                    f"File size ({actual_size:,} bytes) exceeds caveat limit "
                    f"({max_size:,} bytes)"
                )
        return True

    def verify_type(self, actual_type: str) -> bool:
        """Verify file type against type caveat.

        Args:
            actual_type: Actual file extension (without dot)

        Returns:
            bool: True if type matches

        Raises:
            ValueError: If type doesn't match caveat
        """
        if 'file_type' in self.caveats:
            allowed_type = self.caveats['file_type']
            if actual_type.lower() != allowed_type.lower():
                raise ValueError(
                    f"File type '{actual_type}' does not match "
                    f"required type '{allowed_type}'"
                )
        return True

    def verify_hash(self, actual_hash: str) -> bool:
        """Verify file hash against hash caveat.

        Args:
            actual_hash: Computed SHA-256 hash of file data

        Returns:
            bool: True if hash matches

        Raises:
            ValueError: If hash doesn't match (data integrity compromised)
        """
        if 'file_hash' in self.caveats:
            expected_hash = self.caveats['file_hash']
            if not hmac.compare_digest(actual_hash, expected_hash):
                raise ValueError("File hash mismatch - data integrity compromised")
        return True

    def verify_all(self, file_bytes: bytes, filename: str = None) -> bool:
        """Run all applicable verifications.

        Args:
            file_bytes: The file data bytes
            filename: Optional filename for type verification

        Returns:
            bool: True if all verifications pass

        Raises:
            ValueError: If any verification fails
        """
        self.verify_size(len(file_bytes))
        self.verify_hash(hashlib.sha256(file_bytes).hexdigest())

        if filename:
            _, ext = os.path.splitext(filename)
            if ext:
                self.verify_type(ext[1:])  # Remove the dot

        return True


class HVYMDataToken(StellarSharedKeyTokenBuilder):
    """Enhanced data token class that extends StellarSharedKeyTokenBuilder with file storage functionality."""

    # Size limits
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB soft limit (warning)
    WARN_FILE_SIZE = 5 * 1024 * 1024  # 5 MB warning threshold
    CHUNK_SIZE = 1024 * 1024  # 1 MB chunk size for large files

    def __init__(self,
                senderKeyPair: Stellar25519KeyPair,
                receiverPub: str,
                file_path: str = None,
                file_data: bytes = None,
                filename: str = None,
                data: dict = None,
                caveats: dict = None,
                expires_in: int = None):
        """Initialize a new HVYM data token with file storage capability.

        Args:
            senderKeyPair: The sender's key pair
            receiverPub: The receiver's public key (base64 URL-safe encoded)
            file_path: Optional path to file to read and serialize
            file_data: Optional raw file data bytes to store directly
            filename: Optional filename for metadata when using file_data
            data: Optional dictionary of data to encrypt and store (legacy support)
            caveats: Optional dictionary of caveats to add to the token
            expires_in: Optional number of seconds until the token expires
        """

        # Determine the secret data to store
        secret_data = None
        self._file_info = {}

        if file_data is not None:
            # Use provided file data directly (prioritize over file_path)
            secret_data = self._serialize_bytes(file_data, filename)
            self._file_info['source'] = 'file_data'
            self._file_info['size'] = len(file_data)
            if filename:
                self._file_info['filename'] = os.path.basename(filename)
        elif file_path is not None:
            # Read and serialize file from path
            secret_data = self._serialize_file(file_path)
            self._file_info['source'] = 'file_path'
            self._file_info['path'] = file_path
        elif data is not None:
            # Legacy support for dictionary data
            secret_data = json.dumps(data)
            self._file_info['source'] = 'dict_data'
            self._file_info['size'] = len(secret_data)

        # Initialize parent class as SECRET token with serialized data
        super().__init__(
            senderKeyPair=senderKeyPair,
            receiverPub=receiverPub,
            token_type=TokenType.SECRET,
            caveats=caveats,
            secret=secret_data,
            expires_in=expires_in
        )
        
        # Store original data for potential access
        self._data = data
        self._file_path = file_path
        self._file_data = file_data

    def _check_size(self, size: int, source: str):
        """Check file size against limits and warn if exceeded.

        Args:
            size: File size in bytes
            source: Source description for warning message
        """
        if size > self.MAX_FILE_SIZE:
            warnings.warn(
                f"File size ({size:,} bytes) exceeds recommended maximum "
                f"({self.MAX_FILE_SIZE:,} bytes). Source: {source}. "
                f"Large tokens may cause performance issues.",
                UserWarning,
                stacklevel=4
            )
        elif size > self.WARN_FILE_SIZE:
            warnings.warn(
                f"Large file ({size:,} bytes) may cause performance issues. "
                f"Consider using smaller files for token storage.",
                UserWarning,
                stacklevel=4
            )

    def _serialize_file(self, file_path: str) -> str:
        """Read and serialize a file into a base64-encoded string.

        Uses chunked reading for memory efficiency with large files.

        Args:
            file_path: Path to the file to serialize

        Returns:
            str: Base64-encoded serialized file data with metadata
        """
        try:
            # Get file metadata first
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size

            # Check size limits (soft warning)
            self._check_size(file_size, file_path)

            # Read file in chunks for memory efficiency
            chunks = []
            file_hash = hashlib.sha256()

            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    file_hash.update(chunk)
                    chunks.append(chunk)

            # Combine chunks
            file_bytes = b''.join(chunks)

            # Create metadata
            metadata = {
                'filename': os.path.basename(file_path),
                'size': file_size,
                'modified': file_stat.st_mtime,
                'encoding': 'base64',
                'type': 'file_data',
                'hash': file_hash.hexdigest()
            }

            # Encode file data
            encoded_data = base64.b64encode(file_bytes).decode('utf-8')

            # Create serialized format
            serialized = json.dumps({
                'metadata': metadata,
                'data': encoded_data
            })

            # Store file info
            self._file_info.update(metadata)

            return serialized

        except Exception as e:
            raise ValueError(f"Failed to serialize file {file_path}: {str(e)}")
    
    def _serialize_bytes(self, file_data: bytes, file_path: str = None) -> str:
        """Serialize raw bytes into a base64-encoded string.

        Args:
            file_data: Raw file data bytes
            file_path: Optional file path for metadata

        Returns:
            str: Base64-encoded serialized file data with metadata
        """
        # Check size limits (soft warning)
        source = file_path if file_path else "<bytes>"
        self._check_size(len(file_data), source)

        # Calculate hash
        file_hash = hashlib.sha256(file_data).hexdigest()

        # Create metadata
        metadata = {
            'size': len(file_data),
            'encoding': 'base64',
            'type': 'file_data',
            'hash': file_hash
        }

        if file_path:
            metadata['filename'] = os.path.basename(file_path)

        # Encode file data
        encoded_data = base64.b64encode(file_data).decode('utf-8')

        # Create serialized format
        serialized = json.dumps({
            'metadata': metadata,
            'data': encoded_data
        })

        return serialized
    
    def get_file_info(self) -> dict:
        """Get information about the stored file.
        
        Returns:
            dict: File metadata information
        """
        return self._file_info.copy()
    
    def get_data(self) -> dict:
        """Get the original data that was stored in this token (legacy support).
        
        Returns:
            dict: The original data dictionary, or None if no data was provided
        """
        return self._data.copy() if self._data is not None else None
    
    def extract_file_data(self, verifier: 'StellarSharedKeyTokenVerifier',
                          verify_hash: bool = True,
                          enforce_caveats: bool = True) -> bytes:
        """Extract and decode file data from a verified token.

        Args:
            verifier: A verified token verifier instance
            verify_hash: Whether to verify file hash if caveat exists (default: True)
            enforce_caveats: Whether to enforce all file caveats (size, type, hash).
                           If True, raises ValueError on caveat violations.
                           Default: True

        Returns:
            bytes: The original file data

        Raises:
            ValueError: If token verification fails, data extraction fails,
                       hash mismatch, or caveat violation (when enforce_caveats=True)
        """
        if not verifier.valid():
            raise ValueError("Token verification failed")

        try:
            # Get the secret data
            secret_data = verifier.secret()

            # Parse the serialized format
            parsed_data = json.loads(secret_data)

            if parsed_data.get('metadata', {}).get('type') != 'file_data':
                raise ValueError("Token does not contain file data")

            # Decode the file data
            encoded_data = parsed_data['data']
            file_bytes = base64.b64decode(encoded_data.encode('utf-8'))

            # Get metadata for verification
            metadata = parsed_data.get('metadata', {})
            filename = metadata.get('filename')

            # Enforce caveats if enabled
            if enforce_caveats:
                caveats = verifier._get_caveats()
                caveat_verifier = FileCaveatVerifier(caveats)
                # Verify size and type
                caveat_verifier.verify_size(len(file_bytes))
                if filename:
                    _, ext = os.path.splitext(filename)
                    if ext:
                        caveat_verifier.verify_type(ext[1:])
                # Only verify hash if verify_hash is True
                if verify_hash:
                    caveat_verifier.verify_hash(hashlib.sha256(file_bytes).hexdigest())
            elif verify_hash:
                # Legacy behavior: only verify hash
                caveats = verifier._get_caveats()
                if 'file_hash' in caveats:
                    computed_hash = hashlib.sha256(file_bytes).hexdigest()
                    if computed_hash != caveats['file_hash']:
                        raise ValueError("File hash mismatch - data integrity compromised")

            return file_bytes

        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Failed to extract file data: {str(e)}")

    def save_to_file(self, verifier: 'StellarSharedKeyTokenVerifier', output_path: str):
        """Extract file data from token and save to specified path.
        
        Args:
            verifier: A verified token verifier instance
            output_path: Path where to save the extracted file
            
        Raises:
            ValueError: If token verification fails or file saving fails
        """
        file_data = self.extract_file_data(verifier)
        
        try:
            with open(output_path, 'wb') as f:
                f.write(file_data)
        except Exception as e:
            raise ValueError(f"Failed to save file to {output_path}: {str(e)}")
    
    def add_file_caveat(self, key: str, value: str):
        """Add a caveat related to the file content.
        
        Args:
            key: The caveat key
            value: The caveat value
        """
        self._token.add_first_party_caveat(f'file_{key} = {value}')
    
    def add_file_type_caveat(self, file_type: str):
        """Add a caveat specifying the type of file stored.
        
        Args:
            file_type: The type of file (e.g., 'pdf', 'image', 'document', etc.)
        """
        self.add_file_caveat('type', file_type)
    
    def add_file_size_caveat(self, max_size: int):
        """Add a caveat specifying the maximum expected file size.
        
        Args:
            max_size: Maximum expected file size in bytes
        """
        self.add_file_caveat('max_size', str(max_size))
    
    def add_file_hash_caveat(self, expected_hash: str):
        """Add a caveat specifying the expected file hash.

        Args:
            expected_hash: Expected SHA-256 hash of the file
        """
        self.add_file_caveat('hash', expected_hash)

    @staticmethod
    def extract_from_token(serialized_token: str,
                          receiver_keypair: Stellar25519KeyPair,
                          verify_hash: bool = True,
                          enforce_caveats: bool = True) -> tuple:
        """Extract file data directly from a serialized token.

        This is a convenience method that handles verification and extraction
        in a single call without needing a separate HVYMDataToken instance.

        Args:
            serialized_token: The serialized token string
            receiver_keypair: The receiver's keypair for decryption
            verify_hash: Whether to verify file hash if caveat exists (default: True)
            enforce_caveats: Whether to enforce all file caveats (size, type, hash).
                           If True, raises ValueError on caveat violations.
                           Default: True

        Returns:
            tuple: (file_bytes, metadata_dict) where metadata contains file info

        Raises:
            ValueError: If token verification fails, extraction fails,
                       hash mismatch, or caveat violation (when enforce_caveats=True)
        """
        # Create verifier (use new parameter name)
        verifier = StellarSharedKeyTokenVerifier(
            receiverKeyPair=receiver_keypair,
            serializedToken=serialized_token,
            token_type=TokenType.SECRET
        )

        if not verifier.valid():
            raise ValueError("Token verification failed")

        try:
            # Get the secret data
            secret_data = verifier.secret()

            # Parse the serialized format
            parsed_data = json.loads(secret_data)

            if parsed_data.get('metadata', {}).get('type') != 'file_data':
                raise ValueError("Token does not contain file data")

            # Decode the file data
            encoded_data = parsed_data['data']
            file_bytes = base64.b64decode(encoded_data.encode('utf-8'))

            # Get metadata
            metadata = parsed_data.get('metadata', {})
            filename = metadata.get('filename')

            # Enforce caveats if enabled
            if enforce_caveats:
                caveats = verifier._get_caveats()
                caveat_verifier = FileCaveatVerifier(caveats)
                # Verify size and type
                caveat_verifier.verify_size(len(file_bytes))
                if filename:
                    _, ext = os.path.splitext(filename)
                    if ext:
                        caveat_verifier.verify_type(ext[1:])
                # Only verify hash if verify_hash is True
                if verify_hash:
                    caveat_verifier.verify_hash(hashlib.sha256(file_bytes).hexdigest())
            elif verify_hash:
                # Legacy behavior: only verify hash
                caveats = verifier._get_caveats()
                if 'file_hash' in caveats:
                    computed_hash = hashlib.sha256(file_bytes).hexdigest()
                    if computed_hash != caveats['file_hash']:
                        raise ValueError("File hash mismatch - data integrity compromised")

            return file_bytes, metadata

        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Failed to extract file data: {str(e)}")

    @classmethod
    def create_from_file(cls,
                        senderKeyPair: Stellar25519KeyPair,
                        receiverPub: str,
                        file_path: str,
                        expires_in: int = 3600):
        """Convenience method to create a file token from file path.

        Args:
            senderKeyPair: The sender's key pair
            receiverPub: The receiver's public key
            file_path: Path to the file to store
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            HVYMDataToken: Configured file token
        """
        token = cls(
            senderKeyPair=senderKeyPair,
            receiverPub=receiverPub,
            file_path=file_path,
            expires_in=expires_in
        )

        # Add file-specific caveats
        file_stat = os.stat(file_path)
        token.add_file_size_caveat(file_stat.st_size)

        # Add file type caveat based on extension
        _, ext = os.path.splitext(file_path)
        if ext:
            token.add_file_type_caveat(ext[1:].lower())  # Remove the dot

        # Add file hash caveat for integrity verification
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        token.add_file_hash_caveat(file_hash)

        return token

    @classmethod
    def create_from_bytes(cls,
                         senderKeyPair: Stellar25519KeyPair,
                         receiverPub: str,
                         file_data: bytes,
                         filename: str = None,
                         expires_in: int = 3600):
        """Convenience method to create a file token from raw bytes.

        Args:
            senderKeyPair: The sender's key pair
            receiverPub: The receiver's public key
            file_data: Raw file data bytes
            filename: Optional filename for metadata
            expires_in: Token expiration time in seconds (default: 1 hour)

        Returns:
            HVYMDataToken: Configured file token
        """
        token = cls(
            senderKeyPair=senderKeyPair,
            receiverPub=receiverPub,
            file_data=file_data,
            filename=filename,
            expires_in=expires_in
        )

        # Add file-specific caveats
        token.add_file_size_caveat(len(file_data))

        # Add file type caveat if filename provided with extension
        if filename:
            _, ext = os.path.splitext(filename)
            if ext:
                token.add_file_type_caveat(ext[1:].lower())  # Remove the dot

        # Add file hash caveat for integrity verification
        file_hash = hashlib.sha256(file_data).hexdigest()
        token.add_file_hash_caveat(file_hash)

        return token