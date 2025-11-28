# KREL

[![PyPI](https://img.shields.io/pypi/v/krel)](https://pypi.org/project/krel/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Muran-prog/krel/blob/main/LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/krel)](https://pypi.org/project/krel/)

Secure streaming file encryption with constant memory usage.

## Features

- **Simple API** - Encrypt files with 3 lines of code
- **Streaming** - Process unlimited file sizes with O(1) memory
- **Instant rekey** - Change passwords in constant time without re-encryption
- **Battle-tested crypto** - XChaCha20-Poly1305, Argon2id, BLAKE3
- **Safe by default** - Automatic password zeroization

## Install

```bash
pip install krel
```

## Quick Start

```python
from krel import encrypt, decrypt, rekey

# Encrypt
encrypt("file.pdf", "file.pdf.krel", "password")

# Decrypt
decrypt("file.pdf.krel", "file.pdf", "password")

# Change password instantly
rekey("file.pdf.krel", "old-password", "new-password")
```

## Usage

### Basic Operations

```python
from krel import encrypt, decrypt, verify_password

# Encrypt a file
encrypt("document.txt", "document.txt.krel", "my-password")

# Decrypt
decrypt("document.txt.krel", "document.txt", "my-password")

# Check password without decrypting
if verify_password("document.txt.krel", "my-password"):
    print("Correct password")
```

### Password Change

```python
from krel import rekey

# O(1) password change - no re-encryption needed
rekey("file.krel", "old-password", "new-password")
```

### Error Handling

```python
from krel import decrypt, AuthenticationError, IntegrityError

try:
    decrypt("file.krel", "output.txt", "password")
except AuthenticationError:
    print("Wrong password")
except IntegrityError:
    print("File corrupted")
```

### Async API

For large files or high performance:

```python
from krel import encrypt_async, decrypt_async

await encrypt_async("large.iso", "large.iso.krel", "password")
await decrypt_async("large.iso.krel", "large.iso", "password")
```

## API

### Functions

- `encrypt(source, dest, password)` - Encrypt a file
- `decrypt(source, dest, password)` - Decrypt a file
- `rekey(path, old_pass, new_pass)` - Change password
- `verify(path) -> bool` - Check file integrity
- `verify_password(path, password) -> bool` - Verify password

All functions have async versions: `encrypt_async()`, `decrypt_async()`, etc.

### Exceptions

- `KrelError` - Base exception
- `AuthenticationError` - Wrong password
- `IntegrityError` - File corrupted

## Security

### Cryptography

- **Encryption**: XChaCha20-Poly1305 (AEAD)
- **KDF**: Argon2id (256 MB, 3 iterations)
- **Hashing**: BLAKE3
- **Chunk size**: 64 KiB

### Memory Safety

- Passwords automatically zeroed after use
- Constant memory usage regardless of file size
- Secure key wrapping with commitment

## Performance

- **Throughput**: ~500 MB/s (CPU-dependent)
- **Memory**: ~130 KiB constant
- **Rekey**: O(n) but no decryption/encryption

## File Format

```
Header (128 bytes)
├─ Magic: "KREL"
├─ Version: 1
├─ Salt: 16 bytes
├─ Nonce base: 16 bytes
├─ Wrapped DEK: 48 bytes
└─ Commitment: 32 bytes

Encrypted chunks
└─ Chunk: 65552 bytes (64 KiB + 16 byte tag)

Trailer (36 bytes)
├─ Integrity hash: 32 bytes
└─ Magic: "KREL"
```

## Examples

See [examples/](examples/) directory for more usage patterns.

## License

MIT - see [LICENSE](LICENSE) file.

## Author

[Muran-prog](https://github.com/Muran-prog)
