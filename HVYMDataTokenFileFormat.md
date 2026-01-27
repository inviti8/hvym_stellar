# HVYMDataToken File Format Enhancement Plan

## Overview

This document outlines the plan to add enhanced convenience methods to the `HVYMDataToken` class for working with `.hvym` token files. The `.hvym` extension will serve as a unique, recognizable file format for serialized HVYM data tokens.

## Current State

The `HVYMDataToken` class already has basic file I/O methods:

```python
# Save token to file
token.save_token_to_file("token.hvym")

# Load and extract from file
file_bytes, metadata = HVYMDataToken.load_token_from_file("token.hvym", receiver_kp)
```

### Current Limitations

1. No automatic `.hvym` extension handling
2. No file format validation (magic bytes/header)
3. No distinction between `.hvym` files and plain text files
4. No version information in saved files
5. No convenience methods for common patterns (e.g., extract directly to file)

---

## Proposed Enhancements

### 1. File Format Specification

The `.hvym` file format will have a structured header followed by the token data:

```
┌────────────────────────────────────────────────────────┐
│  HVYM Token File Format v1                             │
├────────────────────────────────────────────────────────┤
│  Magic Bytes (8 bytes): "HVYMTOKN"                     │
│  Version (2 bytes): 0x01 0x00 (version 1.0)            │
│  Flags (2 bytes): Reserved for future use              │
│  Header Length (4 bytes): Length of JSON header        │
│  JSON Header: Metadata about the token                 │
│  Token Data: Serialized token string                   │
└────────────────────────────────────────────────────────┘
```

**JSON Header Contents:**
```json
{
  "version": "1.0",
  "created_at": "2024-01-15T10:30:00Z",
  "original_filename": "document.pdf",
  "file_size": 102400,
  "file_hash": "sha256:abc123...",
  "token_type": "biscuit"
}
```

### 2. New Convenience Methods

#### 2.1 `to_hvym_file(path: str, auto_extension: bool = True) -> str`

Instance method to serialize token to a `.hvym` file.

```python
def to_hvym_file(self, path: str, auto_extension: bool = True) -> str:
    """
    Save the token to a .hvym file with proper format header.

    Args:
        path: Output file path
        auto_extension: If True, automatically append .hvym if not present

    Returns:
        The actual path where the file was saved

    Example:
        token = HVYMDataToken.create_from_file(sender_kp, receiver_pub, "doc.pdf")
        saved_path = token.to_hvym_file("my_token")  # Creates "my_token.hvym"
    """
```

**Features:**
- Automatically appends `.hvym` extension if missing
- Writes magic bytes and header for format identification
- Returns the actual saved path
- Validates write permissions before attempting

#### 2.2 `from_hvym_file(path: str, receiver_keypair, verify_hash: bool = True) -> Tuple[bytes, dict]`

Static/class method to decrypt and extract data from a `.hvym` file.

```python
@staticmethod
def from_hvym_file(
    path: str,
    receiver_keypair: Stellar25519KeyPair,
    verify_hash: bool = True
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Load and decrypt data from a .hvym token file.

    Args:
        path: Path to the .hvym file
        receiver_keypair: Keypair for decryption
        verify_hash: Whether to verify file integrity

    Returns:
        Tuple of (file_bytes, metadata_dict)

    Raises:
        ValueError: If file is not a valid .hvym format

    Example:
        data, meta = HVYMDataToken.from_hvym_file("my_token.hvym", receiver_kp)
        with open(meta['filename'], 'wb') as f:
            f.write(data)
    """
```

**Features:**
- Validates magic bytes to ensure proper `.hvym` format
- Provides clear error messages for invalid files
- Extracts header metadata before decryption
- Supports both v1 format and legacy plain-text tokens (backward compatibility)

#### 2.3 `extract_to_file(path: str, receiver_keypair, output_dir: str = None) -> str`

Static method to extract directly from `.hvym` file to the original file.

```python
@staticmethod
def extract_to_file(
    hvym_path: str,
    receiver_keypair: Stellar25519KeyPair,
    output_dir: str = None,
    output_filename: str = None
) -> str:
    """
    Extract file data from .hvym token and save directly to disk.

    Args:
        hvym_path: Path to the .hvym token file
        receiver_keypair: Keypair for decryption
        output_dir: Directory to save the file (default: same as hvym file)
        output_filename: Override the output filename (default: use original name)

    Returns:
        Path to the extracted file

    Example:
        # Extract to same directory with original filename
        extracted = HVYMDataToken.extract_to_file("doc.hvym", receiver_kp)
        print(f"Extracted: {extracted}")  # "document.pdf"

        # Extract to specific directory
        extracted = HVYMDataToken.extract_to_file("doc.hvym", receiver_kp, "/tmp")
    """
```

#### 2.4 `validate_hvym_file(path: str) -> dict`

Static method to validate a `.hvym` file without decrypting.

```python
@staticmethod
def validate_hvym_file(path: str) -> Dict[str, Any]:
    """
    Validate a .hvym file and return its header metadata.

    This can be used to check if a file is valid without needing
    the receiver's keypair for decryption.

    Args:
        path: Path to the .hvym file

    Returns:
        Dictionary with file metadata from header:
        {
            'valid': True,
            'version': '1.0',
            'created_at': '2024-01-15T10:30:00Z',
            'original_filename': 'document.pdf',
            'file_size': 102400,
            'token_type': 'biscuit'
        }

    Raises:
        ValueError: If file is not a valid .hvym format
    """
```

### 3. Constants and Configuration

```python
class HVYMDataToken:
    # File format constants
    HVYM_EXTENSION = '.hvym'
    HVYM_MAGIC_BYTES = b'HVYMTOKN'
    HVYM_FORMAT_VERSION = (1, 0)

    # For backward compatibility with plain-text token files
    LEGACY_FORMAT_SUPPORT = True
```

### 4. Backward Compatibility

The new methods will maintain full backward compatibility:

1. **Reading legacy files**: `from_hvym_file()` will detect plain-text token files (no magic bytes) and process them using the existing `load_token_from_file()` logic

2. **Existing methods unchanged**: `save_token_to_file()` and `load_token_from_file()` remain available for users who prefer plain-text format

3. **Format detection**: Automatic detection based on magic bytes presence

---

## Implementation Tasks

### Phase 1: Core File Format

- [ ] Define `HVYM_MAGIC_BYTES` and `HVYM_FORMAT_VERSION` constants
- [ ] Implement `_write_hvym_header()` internal method
- [ ] Implement `_read_hvym_header()` internal method
- [ ] Implement `_is_hvym_format()` format detection helper

### Phase 2: Convenience Methods

- [ ] Implement `to_hvym_file()` with auto-extension handling
- [ ] Implement `from_hvym_file()` with format validation
- [ ] Implement `extract_to_file()` for one-step extraction
- [ ] Implement `validate_hvym_file()` for validation without decryption

### Phase 3: Testing

- [ ] Add tests for new file format with magic bytes
- [ ] Add tests for auto-extension behavior
- [ ] Add tests for backward compatibility with legacy files
- [ ] Add tests for invalid file format detection
- [ ] Add tests for `extract_to_file()` convenience method

### Phase 4: Documentation

- [ ] Update README with new convenience methods
- [ ] Add usage examples for common workflows
- [ ] Document file format specification

---

## Usage Examples

### Example 1: Basic Save and Load

```python
from hvym_stellar import HVYMDataToken, Stellar25519KeyPair

# Create keypairs
sender_kp = Stellar25519KeyPair.random()
receiver_kp = Stellar25519KeyPair.random()

# Create token with file data
token = HVYMDataToken.create_from_file(
    sender_keypair=sender_kp,
    receiver_pub=receiver_kp.public_key(),
    file_path="secret_document.pdf"
)

# Save to .hvym file (extension auto-added)
saved_path = token.to_hvym_file("my_secure_doc")
print(f"Token saved to: {saved_path}")  # "my_secure_doc.hvym"

# Load and decrypt from .hvym file
file_bytes, metadata = HVYMDataToken.from_hvym_file(
    "my_secure_doc.hvym",
    receiver_kp
)
print(f"Extracted: {metadata['filename']} ({len(file_bytes)} bytes)")
```

### Example 2: One-Step Extraction

```python
# Extract directly to file in one step
extracted_path = HVYMDataToken.extract_to_file(
    "my_secure_doc.hvym",
    receiver_kp,
    output_dir="/tmp/extracted"
)
print(f"File extracted to: {extracted_path}")
```

### Example 3: Validation Before Decryption

```python
# Validate file without decryption (no keypair needed)
info = HVYMDataToken.validate_hvym_file("unknown_file.hvym")
if info['valid']:
    print(f"Valid HVYM file, contains: {info['original_filename']}")
    print(f"File size: {info['file_size']} bytes")
    print(f"Created: {info['created_at']}")
```

### Example 4: Working with Legacy Files

```python
# New methods work with old plain-text token files too
file_bytes, metadata = HVYMDataToken.from_hvym_file(
    "old_token.hvym",  # Plain text token file (no header)
    receiver_kp
)
# Automatically detected as legacy format and processed correctly
```

---

## File Extension Registration (Future)

For future consideration, the `.hvym` extension could be registered with the operating system for:

- Custom file icon display
- "Open with" application association
- MIME type: `application/x-hvym-token`

---

## Security Considerations

1. **Magic bytes are not encryption**: The header metadata is stored in plaintext. Only the token data itself contains encrypted content.

2. **File validation**: `validate_hvym_file()` only confirms format validity, not cryptographic authenticity.

3. **Keypair security**: The receiver's keypair is still required for actual decryption.

4. **No sensitive data in header**: The JSON header contains only non-sensitive metadata (filename, size, timestamps).
