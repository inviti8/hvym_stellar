# hvym_stellar Cryptographic Specification

> **Version**: 2.0
> **Last Updated**: 2026-01-26

This document provides a formal specification of the cryptographic schemes used in hvym_stellar.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Key Types and Conversion](#2-key-types-and-conversion)
3. [Hybrid Encryption Scheme](#3-hybrid-encryption-scheme)
4. [Asymmetric Encryption Scheme](#4-asymmetric-encryption-scheme)
5. [Token System](#5-token-system)
6. [Biscuit Data Token System](#6-biscuit-data-token-system)
7. [Security Properties](#7-security-properties)
8. [Comparison with Standards](#8-comparison-with-standards)

---

## 1. Overview

hvym_stellar provides cryptographic operations built on Stellar keypairs using NaCl/libsodium primitives:

- **Key Agreement**: X25519 (Curve25519 ECDH)
- **Signatures**: Ed25519
- **Authenticated Encryption**: XSalsa20-Poly1305 (NaCl Box)
- **Key Derivation**: SHA-256 with domain separation
- **Access Tokens**: Macaroons with HMAC-SHA256
- **Data Tokens**: Biscuit tokens with Ed25519 (for large file storage)

---

## 2. Key Types and Conversion

### 2.1 Stellar Keypairs

Stellar uses Ed25519 for signing. hvym_stellar converts these to X25519 for encryption:

```
Stellar Secret Key (32 bytes)
    |
    v
Ed25519 Signing Key
    |
    +---> Ed25519 Verify Key (public)
    |         |
    |         v
    |     X25519 Public Key (for ECDH)
    |
    v
X25519 Private Key (for ECDH)
```

### 2.2 Key Derivation

All key derivation uses SHA-256 with domain separation:

```
derived_key = SHA256(domain || salt || shared_secret)
```

Domain constants:
- `hvym_v1:token:sign` - Token signing keys
- `hvym_v1:token:secret` - Token secret encryption
- `hvym_v1:hybrid:encrypt` - Hybrid encryption
- `hvym_v1:asymmetric:encrypt` - Asymmetric encryption
- `hvym_v1:data:file` - Data file tokens

---

## 3. Hybrid Encryption Scheme

The hybrid encryption scheme provides authenticated encryption with sender identity.

### 3.1 Encryption Process

```
Input:
  - plaintext P
  - sender_keypair (sk_s, pk_s) - Ed25519/X25519 keypair
  - receiver_pubkey pk_r - X25519 public key

Process:
  1. Generate random salt S (32 bytes)
  2. Generate random nonce N (24 bytes)
  3. Compute ECDH shared secret: SS = X25519(sk_s, pk_r)
  4. Derive base key: K = SHA256(S || SS)
  5. Sign parameters: sig = Ed25519_Sign(sk_s, S || N) [64 bytes]
  6. Derive encryption keys:
     K_priv = SHA256(K || sig[0:32])
     K_pub = SHA256(K || sig[32:64])
  7. Create ephemeral NaCl Box with (K_priv, K_pub)
  8. Encrypt: C = Box_Encrypt(K_priv, K_pub, N, P)

Output format:
  base64(S) || "|" || base64(N) || "|" || base64(sig) || "|" || hex(C)
```

### 3.2 Decryption Process

```
Input:
  - ciphertext CT in format S|N|sig|C
  - receiver_keypair (sk_r, pk_r)
  - sender_pubkey pk_s (REQUIRED for signature verification)

Process:
  1. Parse CT into components: S, N, sig, C
  2. Compute ECDH shared secret: SS = X25519(sk_r, pk_s)
  3. Derive base key: K = SHA256(S || SS)
  4. Verify signature: Ed25519_Verify(pk_s, S || N, sig)
     - If verification fails, reject immediately
  5. Derive encryption keys:
     K_priv = SHA256(K || sig[0:32])
     K_pub = SHA256(K || sig[32:64])
  6. Create ephemeral NaCl Box with (K_priv, K_pub)
  7. Decrypt: P = Box_Decrypt(K_priv, K_pub, N, C)

Output: plaintext P
```

### 3.3 Wire Format

```
+------------------+---+------------------+---+------------------+---+------------------+
| base64url(salt)  | | | base64url(nonce) | | | base64url(sig)   | | | hex(ciphertext)  |
| 32 bytes encoded | | | 24 bytes encoded | | | 64 bytes encoded | | | variable length  |
+------------------+---+------------------+---+------------------+---+------------------+
                    |                      |                      |
                    +--- pipe separator ---+--- pipe separator ---+
```

---

## 4. Asymmetric Encryption Scheme

Standard X25519 + XSalsa20-Poly1305 without signature authentication.

### 4.1 Encryption Process

```
Input:
  - plaintext P
  - sender_private sk_s
  - receiver_pubkey pk_r

Process:
  1. Generate random salt S (32 bytes) [included but not used in derivation]
  2. Generate random nonce N (24 bytes)
  3. Compute ECDH shared secret: SS = X25519(sk_s, pk_r)
  4. Encrypt using NaCl Box: C = Box_Encrypt(SS, N, P)

Output format:
  base64(S) || "|" || base64(N) || "|" || hex(C)
```

### 4.2 Decryption Process

```
Input:
  - ciphertext CT in format S|N|C
  - receiver_private sk_r
  - sender_pubkey pk_s

Process:
  1. Parse CT into components: S, N, C
  2. Compute ECDH shared secret: SS = X25519(sk_r, pk_s)
  3. Decrypt using NaCl Box: P = Box_Decrypt(SS, N, C)

Output: plaintext P
```

---

## 5. Token System

Tokens use macaroons for capability-based authorization.

### 5.1 Token Types

| Type | Purpose | Contains Secret |
|------|---------|-----------------|
| ACCESS | Authorization grants | No |
| SECRET | Encrypted data storage | Yes (encrypted) |

### 5.2 Token Structure

```
+------------------+
| Macaroon         |
|  - location      |  Token type (ACCESS/SECRET)
|  - identifier    |  sender_pub [| encrypted_secret]
|  - signature     |  HMAC-SHA256
|  - caveats[]     |  Restrictions
+------------------+
| checksum         |  SHA256(serialized)[:8]
+------------------+
```

### 5.3 Signing Key Derivation

```
signing_key = SHA256(domain || shared_secret)

where:
  domain = "hvym_v1:token:sign"
  shared_secret = X25519(sender_private, receiver_public)
```

### 5.4 Secret Encryption (SECRET tokens)

Secrets are encrypted using the hybrid encryption scheme and stored as base64 in the token identifier.

### 5.5 Checksum

The checksum protects against base64 malleability attacks:

```
serialized = macaroon.serialize()  # base64 string
checksum = SHA256(serialized.encode('utf-8')).hexdigest()[:8]
token = serialized + "|" + checksum
```

This detects modifications to the base64 string representation that might not be caught by the macaroon's internal HMAC (which verifies decoded bytes).

### 5.6 Caveat Types

| Caveat | Format | Purpose |
|--------|--------|---------|
| exp | `exp = <unix_timestamp>` | Expiration time |
| file_type | `file_type = <extension>` | File type metadata |
| file_max_size | `file_max_size = <bytes>` | Size limit |
| file_hash | `file_hash = <sha256_hex>` | Integrity verification |

---

## 6. Biscuit Data Token System

HVYMDataToken uses Biscuit tokens for file storage, removing the 16KB size limitation of macaroons.

### 6.1 Shared Account Token Pattern

The key innovation is the **Shared Account Token** pattern, which enables both sender and receiver to use the same signing keypair:

```
Sender                                              Receiver
------                                              --------
1. shared_kp = Keypair.random()
2. Encrypt shared_kp.secret via DH(sender, receiver)
3. Create biscuit signed with shared_kp
                        ─────────────────────────────►
                        [account_token, biscuit_token]
                                                    4. Decrypt shared_kp from account_token
                                                    5. Verify biscuit with shared_kp
                                                    6. Extract file data
```

### 6.2 StellarSharedAccountTokenBuilder

Creates a macaroon-based token containing an encrypted shared keypair:

```
Input:
  - sender_keypair (sk_s, pk_s)
  - receiver_pubkey pk_r
  - expires_in (optional)

Process:
  1. Generate random shared keypair: shared_kp = Keypair.random()
  2. Encode secret: secret_hex = shared_kp.raw_secret_key().hex()
  3. Create SECRET token with encrypted secret_hex
  4. Add caveats: token_type=shared_account, shared_pub=shared_kp.public_key

Output: Macaroon token with encrypted shared keypair
```

### 6.3 Biscuit Token Structure

```
+-------------------------+
| Biscuit Token           |
|  - Authority Block      |
|    - issuer(sender_pub) |
|    - shared_account(G..)|
|    - created(timestamp) |
|    - expires(timestamp) |
|    - file_name(...)     |
|    - file_size(...)     |
|    - file_hash(...)     |
|    - file_data(base64)  |
|  - Ed25519 Signature    |  Signed by shared_keypair
+-------------------------+
```

### 6.4 Combined Token Format

HVYMDataToken serializes as a combined format:

```
+------------------+------------------+------------------+
| account_token    | DELIMITER        | biscuit_b64      |
| (macaroon)       | |HVYM_BISCUIT|   | (base64)         |
+------------------+------------------+------------------+
```

Example:
```
MDAxNGxvY2F0aW9uI...|23abc123|HVYM_BISCUIT|En0KEwoEZmlsZRI...
```

### 6.5 Key Exchange Process

**Sender (Token Creation):**
```
1. account_token = StellarSharedAccountTokenBuilder(
       senderKeyPair, receiverPub, expires_in
   )
   └─► Internally: shared_kp = Keypair.random()

2. shared_kp = account_token.shared_keypair

3. biscuit = BiscuitBuilder(facts).build(shared_kp.private_key)

4. output = account_token.serialize() + DELIMITER + biscuit.to_base64()
```

**Receiver (Token Extraction):**
```
1. Split token by DELIMITER → [account_token, biscuit_b64]

2. shared_kp = StellarSharedAccountTokenBuilder.extract_shared_keypair(
       account_token, receiverKeyPair
   )
   └─► Decrypts shared secret using DH(receiver, sender)
   └─► Reconstructs Keypair from secret

3. biscuit = Biscuit.from_base64(biscuit_b64, shared_kp.public_key)
   └─► Verifies Ed25519 signature

4. Extract file_data fact from biscuit
```

### 6.6 Stellar to Biscuit Key Conversion

Both Stellar and Biscuit use Ed25519:

```python
# Stellar keypair to Biscuit keypair
secret_hex = stellar_kp.raw_secret_key().hex()
biscuit_private = PrivateKey(f"ed25519-private/{secret_hex}")
biscuit_kp = KeyPair.from_private_key(biscuit_private)

# The Ed25519 keys are identical
assert stellar_kp.public_key == biscuit_kp.public_key  # (modulo encoding)
```

### 6.7 Biscuit Fact Schema

```datalog
// Token metadata
issuer($stellar_address)        // Sender's Stellar G... address
shared_account($stellar_addr)   // Shared keypair's G... address
created($timestamp)             // Unix timestamp
expires($timestamp)             // Expiration timestamp

// File metadata
file_name($name)                // Original filename
file_size($bytes)               // File size in bytes
file_hash($sha256_hex)          // SHA-256 hash

// File content
file_data($base64_content)      // Base64-encoded file data
```

### 6.8 Backward Compatibility

HVYMDataToken.extract_from_token() auto-detects token format:

```python
if "|HVYM_BISCUIT|" in token:
    # New biscuit format
    return _extract_biscuit_token(token, receiver_kp)
else:
    # Legacy macaroon format
    return _extract_macaroon_token(token, receiver_kp)
```

---

## 7. Security Properties

### 7.1 Encryption Properties

| Property | Hybrid | Asymmetric |
|----------|--------|------------|
| Confidentiality | Yes (XSalsa20) | Yes (XSalsa20) |
| Integrity | Yes (Poly1305) | Yes (Poly1305) |
| Authenticity | Yes (Ed25519 signature) | No |
| Forward Secrecy | No (static keys) | No (static keys) |
| Replay Protection | Partial (random nonce) | Partial (random nonce) |

### 7.2 Token Properties

| Property | Macaroons | Biscuits |
|----------|-----------|----------|
| Unforgeable | Yes (HMAC-SHA256) | Yes (Ed25519) |
| Attenuable | Yes (first-party caveats) | Yes (blocks) |
| Delegatable | Limited | Yes (attenuation) |
| Tamper-evident | Yes (HMAC + checksum) | Yes (signature) |
| Max Payload | ~16KB | Unlimited |

### 7.3 Biscuit Data Token Security

| Property | Mechanism |
|----------|-----------|
| Key Confidentiality | Shared keypair encrypted via X25519 ECDH + XSalsa20-Poly1305 |
| Key Integrity | Poly1305 MAC on encrypted shared keypair |
| Sender Authentication | Ed25519 signature in account token (hybrid mode) |
| File Authenticity | Ed25519 signature on biscuit (shared keypair) |
| File Integrity | SHA-256 hash stored in biscuit facts |
| Replay Protection | Expiration timestamps in both tokens |

### 7.4 Threat Model

**Protected against:**
- Passive eavesdropping
- Message modification
- Sender impersonation (hybrid mode with verification)
- Token forgery
- Base64 malleability attacks

**Not protected against:**
- Key compromise
- Side-channel attacks
- Replay attacks (application must handle)
- Traffic analysis

---

## 8. Comparison with Standards

### 8.1 vs HPKE (RFC 9180)

| Aspect | hvym_stellar | HPKE |
|--------|--------------|------|
| KEM | X25519 | DHKEM(X25519) |
| KDF | SHA256(salt \|\| secret) | HKDF-SHA256 |
| AEAD | XSalsa20-Poly1305 | ChaCha20-Poly1305 |
| Auth | Ed25519 signature | AuthPSK mode |
| Standard | No | Yes (RFC 9180) |

### 8.2 vs NaCl Box

| Aspect | hvym_stellar Hybrid | Standard NaCl Box |
|--------|---------------------|-------------------|
| Key derivation | SHA256 with salt | X25519 direct |
| Authentication | Ed25519 signature | None (anonymous) |
| Sender identity | Verifiable | Not verifiable |

### 8.3 vs ECIES

| Aspect | hvym_stellar | ECIES |
|--------|--------------|-------|
| Ephemeral keys | No | Yes |
| Forward secrecy | No | Yes |
| Standard | No | IEEE P1363a |

### 8.4 vs Macaroons for Data Storage

| Aspect | HVYMDataToken (Biscuit) | Pure Macaroons |
|--------|-------------------------|----------------|
| Max payload | Unlimited | ~16KB |
| Signing | Ed25519 | HMAC-SHA256 |
| Key sharing | Shared account pattern | N/A |
| Authorization | Datalog | Simple caveats |
| Standard | biscuit-auth | macaroons |

---

## Appendix A: Constants

```python
# Salt size
SALT_SIZE = 32  # bytes

# Nonce size (XSalsa20)
NONCE_SIZE = 24  # bytes

# Ed25519 signature size
SIGNATURE_SIZE = 64  # bytes

# SHA256 output size
HASH_SIZE = 32  # bytes

# Checksum size
CHECKSUM_SIZE = 8  # hex characters (32 bits)

# Default token expiration
DEFAULT_EXPIRATION = 3600  # seconds (1 hour)
```

## Appendix B: Test Vectors

See `test_hvym_stellar.py` and `test_hvym_data_token.py` for comprehensive test vectors.

---

**Document Maintained By**: hvym_stellar Development Team
