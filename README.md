# hvym_stellar

A Python library for secure token generation and verification using Stellar keypairs with support for expiration, access control, secret sharing, and **unlimited file storage** via Biscuit tokens.

## Features

- **Access Tokens**: Macaroon-based tokens with caveats and expiration
- **Secret Sharing**: Encrypted secret transmission between parties
- **Encryption**: Hybrid (signature-based) and asymmetric (X25519) modes
- **File Storage**: Biscuit-based tokens for files of any size (no 16KB limit)
- **Stellar Compatible**: Built on Ed25519/X25519 keys from Stellar SDK

## Installation

```bash
pip install hvym_stellar
```

For file storage support (HVYMDataToken), also install:

```bash
pip install biscuit-auth
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

HVYMDataToken uses Biscuit tokens internally, allowing storage of files of **any size** (no 16KB macaroon limitation).

```python
# Create from file (works with any file size!)
token = HVYMDataToken.create_from_file(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    file_path="large_document.pdf",  # Can be 1MB, 10MB, or larger
    expires_in=86400
)
serialized = token.serialize()

# Create from bytes
token = HVYMDataToken.create_from_bytes(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    file_data=large_binary_data,  # No size limit!
    filename="data.bin",
    expires_in=3600
)

# Extract (static method - recommended)
file_bytes, metadata = HVYMDataToken.extract_from_token(
    serialized_token=serialized,
    receiver_keypair=receiver_kp
)

print(f"Filename: {metadata.get('filename')}")
print(f"Size: {metadata.get('size')} bytes")
print(f"Hash: {metadata.get('hash')}")
```

#### Saving & Loading Tokens from Files

```python
# === SENDER SIDE ===
# Create a token and save it to a file for transmission
token = HVYMDataToken.create_from_file(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    file_path="secret_document.pdf",
    expires_in=86400
)

# Save the token to a file (can be emailed, uploaded, etc.)
token.save_token_to_file("document_token.hvym")
print(f"Token saved! File info: {token.get_file_info()}")

# === RECEIVER SIDE ===
# Load and extract the file from the token
file_bytes, metadata = HVYMDataToken.load_token_from_file(
    file_path="document_token.hvym",
    receiver_keypair=receiver_kp
)

# Save the extracted file
output_filename = metadata.get('filename', 'extracted_file')
with open(output_filename, 'wb') as f:
    f.write(file_bytes)
print(f"Extracted: {output_filename} ({metadata['size']} bytes)")
```

**How it works internally:**
1. A random shared keypair is generated
2. The shared keypair is encrypted and sent via a macaroon (account token)
3. The file data is stored in a Biscuit token signed with the shared keypair
4. Both tokens are combined into a single serialized string

This enables both sender and receiver to verify the token while supporting unlimited file sizes.

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

# Extraction (auto-detects biscuit vs legacy macaroon format)
file_bytes, metadata = HVYMDataToken.extract_from_token(serialized_token, receiver_keypair)

# Caveats (added as Biscuit facts)
token.add_file_type_caveat("pdf")
token.add_file_size_caveat(1048576)
token.add_file_hash_caveat("sha256_hash")

# Get file info
info = token.get_file_info()  # Returns dict with size, hash, filename, etc.

# Save/Load tokens to/from files
token.save_token_to_file("token.hvym")
file_bytes, metadata = HVYMDataToken.load_token_from_file("token.hvym", receiver_kp)
```

### StellarSharedAccountTokenBuilder (Advanced)

For direct access to the shared keypair mechanism:

```python
from hvym_stellar import StellarSharedAccountTokenBuilder

# Create shared account token
account_token = StellarSharedAccountTokenBuilder(
    senderKeyPair=sender_kp,
    receiverPub=receiver_kp.public_key(),
    expires_in=3600
)

# Sender gets the shared keypair
shared_kp = account_token.shared_keypair
print(f"Shared account: {shared_kp.public_key}")

# Serialize and send to receiver
serialized = account_token.serialize()

# Receiver extracts shared keypair
shared_kp = StellarSharedAccountTokenBuilder.extract_shared_keypair(
    serialized_token=serialized,
    receiverKeyPair=receiver_kp
)
# Now both parties have the same keypair for signing/verifying
```

## Encryption Methods Comparison

| Method | Security | Use Case |
|--------|----------|----------|
| `asymmetric_encrypt()` | HIGH - Industry standard X25519 | Recommended for new code |
| `encrypt()` | MODERATE - Hybrid with signatures | Backward compatible |

## Token Comparison

| Feature | Access Tokens | Secret Tokens | Data Tokens (HVYMDataToken) |
|---------|---------------|---------------|----------------------------|
| Backend | Macaroon | Macaroon | Biscuit + Macaroon |
| Max Size | ~16KB | ~16KB | **Unlimited** |
| Signing | HMAC-SHA256 | HMAC-SHA256 | Ed25519 |
| File Storage | No | Limited | **Yes** |

## Security

- Ed25519 signatures authenticate encryption parameters
- SHA-256 hash verification for file tokens
- Tamper-evident checksums on serialized tokens
- 256-bit security foundation

## Version History

- **0.20.0**: HVYMDataToken now uses Biscuit tokens
  - Unlimited file size support (no more 16KB macaroon limit)
  - New `StellarSharedAccountTokenBuilder` for shared keypair exchange
  - Backward compatible - can still read old macaroon-based tokens
  - Requires `biscuit-auth` package for file storage
- **0.19.0**: BREAKING CHANGES - See [HVYM_STELLAR.md](HVYM_STELLAR.md)
  - `recieverPub` → `receiverPub`, `recieverKeyPair` → `receiverKeyPair`
  - `decrypt()` now requires `from_address` parameter
- 0.18.1: Improved crypto methods, nonce signing
- 0.18.0: Added HVYMDataToken for file storage
- 0.17.0: Asymmetric encryption support
- 0.16.0: Asymmetric key derivation

## License

MIT License - See [LICENSE](LICENSE) for details.
