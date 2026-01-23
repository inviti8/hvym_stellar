# hvym_stellar

A Python library for secure token generation and verification using Stellar keypairs. This package provides a robust way to create and verify tokens with support for expiration, access control, secret sharing, and consistent shared key derivation.

## Features

- **Secure Token Generation**: Create cryptographically secure tokens using Stellar keypairs
- **Token Expiration**: Set token expiration times to enhance security
- **Access Control**: Define fine-grained access control through caveats
- **Secret Sharing**: Securely share secrets between parties
- **Consistent Shared Key Derivation**: Reliable cross-instance shared key generation
- **Utility Functions**: Easy extraction of salt/nonce from encrypted data
- **Backward Compatibility**: Support for legacy token verification
- **Timestamp Validation**: Built-in support for token expiration and max age validation

## Installation

```bash
pip install hvym_stellar
```

## Dependencies

- PyNaCl (Python binding to libsodium)
- pymacaroons (Macaroon token support)
- stellar-sdk (Stellar keypair and address handling)
- base58 (For encoding/decoding)
- cryptography (For encryption/decryption)

## Basic Usage

### 1. Creating a Token

```python
from hvym_stellar import StellarSharedKeyTokenBuilder, TokenType
from stellar_sdk import Keypair

# Generate or load Stellar keypairs
sender_kp = Keypair.random()
receiver_kp = Keypair.random()

# Create a new token
token = StellarSharedKeyTokenBuilder(
    sender_kp,
    receiver_kp.public_key,
    token_type=TokenType.ACCESS,
    expires_in=3600,  # 1 hour expiration
    caveats={"user_id": "123", "role": "admin"}
)

# Serialize the token for transmission
serialized_token = token.serialize()
```

### 2. Verifying a Token

```python
from hvym_stellar import StellarSharedKeyTokenVerifier, TokenType

# Verify the token
verifier = StellarSharedKeyTokenVerifier(
    receiver_kp,
    serialized_token,
    TokenType.ACCESS,
    expected_caveats={"user_id": "123"},
    max_age_seconds=3600  # Optional: enforce maximum token age
)

if verifier.valid():
    print("Token is valid!")
    
    # Access token claims
    print("Token expires at:", verifier.get_expiration_time())
    print("Is expired:", verifier.is_expired())
```

### 3. Sharing Secrets

```python
# Sender: Create token with a secret
secret_data = "sensitive-information-here"
token_with_secret = StellarSharedKeyTokenBuilder(
    sender_kp,
    receiver_kp.public_key,
    token_type=TokenType.SECRET,
    secret=secret_data,
    expires_in=300  # 5 minutes
)
serialized_secret_token = token_with_secret.serialize()

# Receiver: Extract the secret
verifier = StellarSharedKeyTokenVerifier(
    receiver_kp,
    serialized_secret_token,
    TokenType.SECRET
)

if verifier.valid():
    try:
        secret = verifier.secret()
        print("Retrieved secret:", secret)
    except ValueError as e:
        print("Failed to retrieve secret:", str(e))
```

### 4. Consistent Shared Key Derivation (Sender-Receiver Model)

```python
from hvym_stellar import StellarSharedKey, StellarSharedDecryption
from hvym_stellar import extract_salt_from_encrypted, extract_nonce_from_encrypted
from stellar_sdk import Keypair

# Generate keypairs
kp1 = Keypair.random()
kp2 = Keypair.random()
sender_kp = Stellar25519KeyPair(kp1)
receiver_kp = Stellar25519KeyPair(kp2)

# === SENDER SIDE ===
# Sender creates shared key and encrypts message
sender_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
message = b"Secret message from sender"
encrypted = sender_key.encrypt(message)

# Sender extracts salt and nonce from encrypted data
salt = extract_salt_from_encrypted(encrypted)
nonce = extract_nonce_from_encrypted(encrypted)

# Sender passes salt/nonce to receiver (via token, message, etc.)
# This could be embedded in a token or sent separately
print(f"Salt to share: {salt.hex()}")
print(f"Nonce to share: {nonce.hex()}")

# === RECEIVER SIDE ===
# Receiver creates shared key using received salt/nonce
receiver_key = StellarSharedKey(receiver_kp, sender_kp.public_key())

# Both derive the same key using the shared salt/nonce
sender_derived = sender_key.shared_secret(salt=salt, nonce=nonce)
receiver_derived = receiver_key.shared_secret(salt=salt, nonce=nonce)
print(f"Keys match: {sender_derived == receiver_derived}")  # True

# Receiver can decrypt the message
receiver_decrypt = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
decrypted = receiver_decrypt.decrypt(encrypted)
print(f"Decrypted message: {decrypted}")  # "Secret message from sender"

# === DETERMINISTIC USAGE ===
# For cases where you just need consistent keys without encryption
shared_key1 = StellarSharedKey(sender_kp, receiver_kp.public_key())
shared_key2 = StellarSharedKey(receiver_kp, sender_kp.public_key())

# Default behavior is deterministic (same across instances)
secret1 = shared_key1.shared_secret()
secret2 = shared_key2.shared_secret()
print(f"Deterministic secrets match: {secret1 == secret2}")  # True
```

### 5. Encryption with Key Reconstruction

```python
from hvym_stellar import extract_salt_from_encrypted, extract_nonce_from_encrypted

# Encrypt data
message = b"Hello, Stellar!"
encrypted = shared_key1.encrypt(message)

# Extract components for later key reconstruction
salt = extract_salt_from_encrypted(encrypted)
nonce = extract_nonce_from_encrypted(encrypted)
print(f"Salt: {len(salt)} bytes, Nonce: {len(nonce)} bytes")

# Reconstruct the exact key used for encryption
reconstructed_key = shared_key1.shared_secret(salt=salt)
print(f"Key reconstruction successful: {reconstructed_key is not None}")

# Decrypt using the reconstructed key
decrypt_key = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
decrypted = decrypt_key.decrypt(encrypted)
print(f"Decrypted: {decrypted}")  # "Hello, Stellar!"
```

### 6. Hash Operations

```python
# Get hash of shared secret
default_hash = shared_key1.hash_of_shared_secret()
print(f"Default hash: {default_hash}")

# Get hash with specific salt
salted_hash = shared_key1.hash_of_shared_secret(salt=salt)
print(f"Salted hash: {salted_hash}")

# Hash consistency across classes
decrypt_hash = decrypt_key.hash_of_shared_secret(salt=salt)
print(f"Hashes match: {salted_hash == decrypt_hash}")  # True
```

### 7. Asymmetric Key Derivation (Recommended for Security)

```python
from hvym_stellar import StellarSharedKey, StellarSharedDecryption
from stellar_sdk import Keypair

# Generate keypairs
kp1 = Keypair.random()
kp2 = Keypair.random()
sender_kp = Stellar25519KeyPair(kp1)
receiver_kp = Stellar25519KeyPair(kp2)

# === ASYMMETRIC SHARED SECRETS ===
# Get raw X25519 shared secrets (most secure approach)
sender_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
receiver_key = StellarSharedDecryption(receiver_kp, sender_kp.public_key())

# Both get the same raw X25519 shared secret
asym_secret1 = sender_key.asymmetric_shared_secret()
asym_secret2 = receiver_key.asymmetric_shared_secret()
print(f"Asymmetric secrets match: {asym_secret1 == asym_secret2}")  # True
print(f"Secret length: {len(asym_secret1)} bytes")  # 32 bytes

# Get hex-encoded version
asym_hex1 = sender_key.asymmetric_shared_secret_as_hex()
asym_hex2 = receiver_key.asymmetric_shared_secret_as_hex()
print(f"Hex secrets match: {asym_hex1 == asym_hex2}")  # True

# Get hash of asymmetric secret
asym_hash1 = sender_key.asymmetric_hash_of_shared_secret()
asym_hash2 = receiver_key.asymmetric_hash_of_shared_secret()
print(f"Hashes match: {asym_hash1 == asym_hash2}")  # True
```

### 8. Asymmetric Encryption (Recommended)

```python
# === SECURE ASYMMETRIC ENCRYPTION ===
# Sender encrypts using standard X25519 pattern
message = b"Secret message using asymmetric encryption"
encrypted = sender_key.encrypt(message)  # Uses proper X25519

# Receiver decrypts using standard X25519 pattern
decrypted = receiver_key.decrypt(encrypted)
print(f"Decrypted: {decrypted}")  # "Secret message using asymmetric encryption"

# === LEGACY ENCRYPTION (Deprecated) ===
# Old method using derived keys (shows deprecation warning)
import warnings

with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    
    encrypted_legacy = sender_key.encrypt_with_derived_key(message)
    decrypted_legacy = receiver_key.decrypt_with_derived_key(encrypted_legacy)
    
    print(f"Legacy decrypted: {decrypted_legacy}")
    print(f"Deprecation warnings: {len(w)}")  # 2 warnings
```

### 9. Migration Guide: Derived to Asymmetric

```python
# === OLD PATTERN (Derived Keys) ===
# This still works but is less secure
old_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
salt = secrets.token_bytes(32)
derived_secret = old_key.shared_secret(salt=salt)
derived_hash = old_key.hash_of_shared_secret(salt=salt)

# === NEW PATTERN (Asymmetric Keys) ===
# More secure, simpler, and industry standard
new_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
asym_secret = new_key.asymmetric_shared_secret()  # No salt needed
asym_hash = new_key.asymmetric_hash_of_shared_secret()  # More secure

# === ENCRYPTION MIGRATION ===
# Old way (deprecated)
old_encrypted = old_key.encrypt_with_derived_key(message)

# New way (recommended)
new_encrypted = new_key.encrypt(message)  # Proper X25519

# Both can be decrypted with the corresponding receiver key
old_decrypted = receiver_key.decrypt_with_derived_key(old_encrypted)
new_decrypted = receiver_key.decrypt(new_encrypted)
```

### 10. Asymmetric vs Derived Methods Comparison

```python
# === SECURITY COMPARISON ===
asymmetric_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
derived_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
salt = secrets.token_bytes(32)

# Asymmetric methods (HIGH security - recommended)
print("=== ASYMMETRIC METHODS ===")
print(f"Raw secret: {asymmetric_key.asymmetric_shared_secret().hex()}")
print(f"Hex secret: {asymmetric_key.asymmetric_shared_secret_as_hex()}")
print(f"Hash: {asymmetric_key.asymmetric_hash_of_shared_secret()}")

# Derived methods (MODERATE security - legacy)
print("\n=== DERIVED METHODS ===")
print(f"Derived secret: {derived_key.shared_secret(salt=salt).hex()}")
print(f"Derived hex: {derived_key.shared_secret_as_hex(salt=salt)}")
print(f"Derived hash: {derived_key.hash_of_shared_secret(salt=salt)}")

# Note: Asymmetric and derived methods produce different results
# Asymmetric uses raw X25519, Derived uses salted SHA-256
```

## Token Types

### Access Tokens
- Used for API authentication and authorization
- Can include custom caveats for access control
- Support expiration and max age validation

### Secret Tokens
- Used for securely sharing sensitive information
- Automatically encrypted using the receiver's public key
- Can be decrypted only by the intended recipient

## Security Considerations

- Always use HTTPS when transmitting tokens
- Set appropriate expiration times for tokens
- Validate all token claims and caveats on the server side
- Rotate encryption keys regularly
- Keep private keys secure and never commit them to version control

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss your ideas.

## API Reference

### StellarSharedKey

```python
# Create shared key
shared_key = StellarSharedKey(sender_keypair, receiver_public_key)

# Get deterministic shared secret (default behavior)
secret = shared_key.shared_secret()

# Get shared secret with specific salt
secret = shared_key.shared_secret(salt=custom_salt)

# Get hex-encoded shared secret
hex_secret = shared_key.shared_secret_as_hex()
hex_secret_with_salt = shared_key.shared_secret_as_hex(salt=custom_salt)

# Get hash of shared secret
hash_value = shared_key.hash_of_shared_secret()
hash_with_salt = shared_key.hash_of_shared_secret(salt=custom_salt)

# Encrypt data (recommended - uses proper X25519)
encrypted = shared_key.encrypt(message_bytes)

# Encrypt data (deprecated - uses derived keys)
encrypted_legacy = shared_key.encrypt_with_derived_key(message_bytes)

# === ASYMMETRIC METHODS (Recommended for Security) ===

# Get raw X25519 shared secret (most secure)
asym_secret = shared_key.asymmetric_shared_secret()

# Get hex-encoded raw X25519 shared secret
asym_hex = shared_key.asymmetric_shared_secret_as_hex()

# Get hash of raw X25519 shared secret
asym_hash = shared_key.asymmetric_hash_of_shared_secret()
```

### StellarSharedDecryption

```python
# Create decryption key
decrypt_key = StellarSharedDecryption(receiver_keypair, sender_public_key)

# Get deterministic shared secret
secret = decrypt_key.shared_secret()

# Get shared secret with specific salt
secret = decrypt_key.shared_secret(salt=extracted_salt)

# Decrypt data (recommended - uses proper X25519)
decrypted = decrypt_key.decrypt(encrypted_data)

# Decrypt data (deprecated - uses derived keys)
decrypted_legacy = decrypt_key.decrypt_with_derived_key(encrypted_data)

# === ASYMMETRIC METHODS (Recommended for Security) ===

# Get raw X25519 shared secret (most secure)
asym_secret = decrypt_key.asymmetric_shared_secret()

# Get hex-encoded raw X25519 shared secret
asym_hex = decrypt_key.asymmetric_shared_secret_as_hex()

# Get hash of raw X25519 shared secret
asym_hash = decrypt_key.asymmetric_hash_of_shared_secret()
```

### Utility Functions

```python
from hvym_stellar import extract_salt_from_encrypted, extract_nonce_from_encrypted, extract_ciphertext_from_encrypted

# Extract components from encrypted data
salt = extract_salt_from_encrypted(encrypted_data)
nonce = extract_nonce_from_encrypted(encrypted_data)
ciphertext = extract_ciphertext_from_encrypted(encrypted_data)
```

## Migration Guide

### From v0.14 to v0.15

The API has been enhanced to support consistent shared key derivation. Existing code continues to work without changes:

```python
# This still works exactly as before
secret = shared_key.shared_secret()
hex_secret = shared_key.shared_secret_as_hex()
hash_value = shared_key.hash_of_shared_secret()
```

New functionality for consistent key derivation using the sender-receiver model:

```python
# === SENDER SIDE ===
# Sender encrypts data and extracts salt/nonce
sender_key = StellarSharedKey(sender_kp, receiver_pub)
encrypted = sender_key.encrypt(message)

# Extract components to share with receiver
salt = extract_salt_from_encrypted(encrypted)
nonce = extract_nonce_from_encrypted(encrypted)

# === RECEIVER SIDE ===
# Receiver creates shared key with received salt/nonce
receiver_key = StellarSharedKey(receiver_kp, sender_pub)

# Both derive the same key
sender_derived = sender_key.shared_secret(salt=salt, nonce=nonce)
receiver_derived = receiver_key.shared_secret(salt=salt, nonce=nonce)

# Cross-class consistency
decrypt_key = StellarSharedDecryption(receiver_kp, sender_pub)
same_secret = sender_derived == decrypt_key.shared_secret(salt=salt)
```

### From v0.15 to v0.16 (Asymmetric Security Upgrade)

Version 0.16 introduces asymmetric key derivation for enhanced security. Existing code continues to work, but we recommend migrating to the new asymmetric methods:

```python
# === OLD PATTERN (v0.15 - Derived Keys) ===
# Still works but has MODERATE security rating
old_key = StellarSharedKey(sender_kp, receiver_pub)
salt = secrets.token_bytes(32)
derived_secret = old_key.shared_secret(salt=salt)
derived_encrypted = old_key.encrypt_with_derived_key(message)

# === NEW PATTERN (v0.16 - Asymmetric Keys) ===
# Recommended - HIGH security rating
new_key = StellarSharedKey(sender_kp, receiver_pub)
asym_secret = new_key.asymmetric_shared_secret()  # No salt needed
asym_encrypted = new_key.encrypt(message)  # Proper X25519

# === MIGRATION BENEFITS ===
# 1. Higher security (HIGH vs MODERATE rating)
# 2. No salt management required
# 3. Industry-standard X25519 encryption
# 4. Simpler API (fewer parameters)
# 5. Better performance (no SHA-256 derivation)

# === GRADUAL MIGRATION ===
# Step 1: Update encryption calls
# Old: encrypted = key.encrypt_with_derived_key(message)
# New: encrypted = key.encrypt(message)

# Step 2: Update shared secret calls
# Old: secret = key.shared_secret(salt=salt)
# New: secret = key.asymmetric_shared_secret()

# Step 3: Update hash calls
# Old: hash_val = key.hash_of_shared_secret(salt=salt)
# New: hash_val = key.asymmetric_hash_of_shared_secret()
```

### Security Comparison

| Feature | v0.15 (Derived) | v0.16 (Asymmetric) | Recommendation |
|---------|-----------------|-------------------|----------------|
| Security Rating | ⚠️ MODERATE | ✅ HIGH | Upgrade to v0.16 |
| Encryption | Self-encryption | Standard X25519 | Use v0.16 |
| Key Derivation | Salted SHA-256 | Raw X25519 | Use v0.16 |
| Salt Management | Required | Not needed | Use v0.16 |
| Performance | Slower (SHA-256) | Faster (direct) | Use v0.16 |
| Industry Standard | No | Yes | Use v0.16 |

### Practical Usage Patterns

#### Token-based Sharing
```python
# Sender includes salt/nonce in token metadata
token = StellarSharedKeyTokenBuilder(sender_kp, receiver_pub, 
    token_type=TokenType.SECRET,
    secret=message,
    caveats={"salt": salt.hex(), "nonce": nonce.hex()}
)

# Receiver extracts salt/nonce from token and derives same key
verifier = StellarSharedKeyTokenVerifier(receiver_kp, token.serialize())
caveats = verifier._get_caveats()
extracted_salt = bytes.fromhex(caveats["salt"])
extracted_nonce = bytes.fromhex(caveats["nonce"])
same_key = StellarSharedKey(receiver_kp, sender_pub).shared_secret(salt=extracted_salt, nonce=extracted_nonce)
```

#### Direct Message Sharing
```python
# Sender sends encrypted message + salt/nonce separately
message_to_send = {
    "encrypted": encrypted.hex(),
    "salt": salt.hex(), 
    "nonce": nonce.hex()
}

# Receiver reconstructs the same key
received_salt = bytes.fromhex(message_to_send["salt"])
received_nonce = bytes.fromhex(message_to_send["nonce"])
receiver_key = StellarSharedKey(receiver_kp, sender_pub).shared_secret(salt=received_salt, nonce=received_nonce)
```

## Version History

- 0.15.0: Added consistent shared key derivation with salt/nonce parameters
- 0.14.0: Fixed shared key consistency issue with random_salt parameter
- 0.13.0: Initial release with token functionality
- 0.9.0: Added timestamp validation and expiration support
