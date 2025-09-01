# hvym_stellar

A Python library for secure token generation and verification using Stellar keypairs. This package provides a robust way to create and verify tokens with support for expiration, access control, and secret sharing.

## Features

- **Secure Token Generation**: Create cryptographically secure tokens using Stellar keypairs
- **Token Expiration**: Set token expiration times to enhance security
- **Access Control**: Define fine-grained access control through caveats
- **Secret Sharing**: Securely share secrets between parties
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

## Version History

- 0.1.0: Initial release
- 0.9.0: Added timestamp validation and expiration support
