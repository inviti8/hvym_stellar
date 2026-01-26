# hvym_stellar

A Python library for secure token generation and verification using Stellar keypairs with support for expiration, access control, secret sharing, and file storage.

## Installation

```bash
pip install hvym_stellar
```

## Quick Start

```python
from hvym_stellar import (
    Stellar25519KeyPair, StellarSharedKey, StellarSharedDecryption,
    StellarSharedKeyTokenBuilder, StellarSharedKeyTokenVerifier,
    HVYMDataToken, TokenType
)
from stellar_sdk import Keypair

# Create keypairs
sender_kp = Stellar25519KeyPair(Keypair.random())
receiver_kp = Stellar25519KeyPair(Keypair.random())
```

## Usage Examples

### 1. Access Tokens

```python
# Create token with caveats
token = StellarSharedKeyTokenBuilder(
    sender_kp,
    receiver_kp.public_key(),
    token_type=TokenType.ACCESS,
    expires_in=3600,
    caveats={"user_id": "123", "role": "admin"}
)
serialized = token.serialize()

# Verify token (caveats must match ALL token caveats)
verifier = StellarSharedKeyTokenVerifier(
    receiver_kp,
    serialized,
    TokenType.ACCESS,
    caveats={"user_id": "123", "role": "admin"}
)

if verifier.valid():
    print("Token valid, expires:", verifier._get_expiration_time())
```

### 2. Secret Sharing

```python
# Sender creates secret token
token = StellarSharedKeyTokenBuilder(
    sender_kp,
    receiver_kp.public_key(),
    token_type=TokenType.SECRET,
    secret="sensitive-data",
    expires_in=300
)
serialized = token.serialize()

# Receiver extracts secret
verifier = StellarSharedKeyTokenVerifier(
    receiver_kp, serialized, TokenType.SECRET
)
if verifier.valid():
    secret = verifier.secret()
```

### 3. Encryption/Decryption (Hybrid)

Uses signature-based format: `salt|nonce|signature|ciphertext`

```python
from hvym_stellar import extract_salt_from_encrypted

# Encrypt
shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
encrypted = shared_key.encrypt(b"Secret message")

# Decrypt (from_address REQUIRED in v0.19+)
decryptor = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
sender_address = sender_kp.base_stellar_keypair().public_key
decrypted = decryptor.decrypt(encrypted, from_address=sender_address)

# Extract components if needed
salt = extract_salt_from_encrypted(encrypted)
```

### 4. Asymmetric Encryption (Recommended)

Standard X25519 encryption - simpler and more secure.

```python
# Encrypt
shared_key = StellarSharedKey(sender_kp, receiver_kp.public_key())
encrypted = shared_key.asymmetric_encrypt(b"Secret message")

# Decrypt (no from_address needed)
decryptor = StellarSharedDecryption(receiver_kp, sender_kp.public_key())
decrypted = decryptor.asymmetric_decrypt(encrypted)

# Shared secrets
secret = shared_key.asymmetric_shared_secret()  # 32 bytes
```

### 5. File Storage (HVYMDataToken)

```python
# Create from file
token = HVYMDataToken.create_from_file(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    file_path="document.pdf",
    expires_in=86400
)
serialized = token.serialize()

# Create from bytes
token = HVYMDataToken.create_from_bytes(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    file_data=b"binary content",
    filename="data.bin",
    expires_in=3600
)

# Extract (static method - recommended)
file_bytes, metadata = HVYMDataToken.extract_from_token(
    serialized_token=serialized,
    receiver_keypair=receiver_kp
)
```

## API Reference

### StellarSharedKey

```python
shared_key = StellarSharedKey(sender_keypair, receiver_public_key)

# Hybrid encryption (signature-based)
encrypted = shared_key.encrypt(message_bytes)

# Asymmetric encryption (recommended)
encrypted = shared_key.asymmetric_encrypt(message_bytes)

# Shared secrets
secret = shared_key.shared_secret()                    # Deterministic
secret = shared_key.shared_secret(salt=custom_salt)    # With salt
secret = shared_key.asymmetric_shared_secret()         # Raw X25519 (recommended)

# Hashes
hash_val = shared_key.hash_of_shared_secret()
hash_val = shared_key.asymmetric_hash_of_shared_secret()
```

### StellarSharedDecryption

```python
decryptor = StellarSharedDecryption(receiver_keypair, sender_public_key)

# Hybrid decryption (from_address REQUIRED in v0.19+)
decrypted = decryptor.decrypt(encrypted, from_address=sender_address)

# Asymmetric decryption (recommended)
decrypted = decryptor.asymmetric_decrypt(encrypted)

# Shared secrets (same as StellarSharedKey)
secret = decryptor.asymmetric_shared_secret()
```

### Utility Functions

```python
from hvym_stellar import (
    extract_salt_from_encrypted,      # 32 bytes
    extract_nonce_from_encrypted,     # 24 bytes
    extract_signature_from_encrypted, # 64 bytes
    extract_ciphertext_from_encrypted # Variable
)
```

### HVYMDataToken

```python
# Factory methods
token = HVYMDataToken.create_from_file(senderKeyPair, receiverPub, file_path, expires_in)
token = HVYMDataToken.create_from_bytes(senderKeyPair, receiverPub, file_data, filename, expires_in)

# Extraction
file_bytes, metadata = HVYMDataToken.extract_from_token(serialized_token, receiver_keypair)

# Caveats
token.add_file_type_caveat("pdf")
token.add_file_size_caveat(1048576)
token.add_file_hash_caveat("sha256_hash")
```

## Encryption Methods Comparison

| Method | Security | Use Case |
|--------|----------|----------|
| `asymmetric_encrypt()` | HIGH - Industry standard X25519 | Recommended for new code |
| `encrypt()` | MODERATE - Hybrid with signatures | Backward compatible |

## Security

- Ed25519 signatures authenticate encryption parameters
- SHA-256 hash verification for file tokens
- Tamper-evident checksums on serialized tokens
- 256-bit security foundation

## Version History

- **0.19.0**: BREAKING CHANGES - See [HVYM_STELLAR.md](HVYM_STELLAR.md)
  - `recieverPub` → `receiverPub`, `recieverKeyPair` → `receiverKeyPair`
  - `decrypt()` now requires `from_address` parameter
- 0.18.1: Improved crypto methods, nonce signing
- 0.18.0: Added HVYMDataToken for file storage
- 0.17.0: Asymmetric encryption support
- 0.16.0: Asymmetric key derivation

## License

MIT License - See [LICENSE](LICENSE) for details.
