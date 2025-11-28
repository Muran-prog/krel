"""
KREL - Secure Streaming File Encryption
========================================

A secure, streaming file encryption engine with O(1) memory usage.

Features:
- Streaming encryption/decryption (unlimited file size)
- XChaCha20-Poly1305 + Argon2id
- O(1) password change (rekey)
- Automatic password zeroization

Basic Usage:
    from krel import encrypt, decrypt, rekey
    
    # Encrypt a file
    encrypt("document.pdf", "document.pdf.krel", "my-password")
    
    # Decrypt
    decrypt("document.pdf.krel", "document.pdf", "my-password")
    
    # Change password (O(1) operation)
    rekey("document.pdf.krel", "old-password", "new-password")

Async Usage:
    from krel import encrypt_async, decrypt_async
    
    await encrypt_async("large.iso", "large.iso.krel", "password")
"""

import asyncio
from typing import Union
from functools import wraps

# Import the core Rust engine
from krel._core import KrelEngine as _KrelEngine

__version__ = "0.1.1"
__all__ = [
    # Sync API
    "encrypt",
    "decrypt",
    "rekey",
    "verify",
    "verify_password",
    # Async API
    "encrypt_async",
    "decrypt_async", 
    "rekey_async",
    "verify_async",
    "verify_password_async",
    # Exceptions
    "KrelError",
    "AuthenticationError",
    "IntegrityError",
]


# ============================================================================
# Exceptions
# ============================================================================

class KrelError(Exception):
    """Base exception for all KREL errors"""
    pass


class AuthenticationError(KrelError):
    """Wrong password or authentication failure"""
    pass


class IntegrityError(KrelError):
    """File integrity check failed - file may be corrupted or tampered"""
    pass


# ============================================================================
# Internal Helpers
# ============================================================================

def _to_bytearray(password: Union[str, bytes, bytearray]) -> bytearray:
    """
    Convert password to bytearray for safe handling.
    
    Security Note:
        - Strings and bytes are immutable and remain in memory
        - bytearray is mutable and will be zeroed after use
        - We create a NEW bytearray each time to avoid reuse bugs
    """
    if isinstance(password, str):
        return bytearray(password.encode('utf-8'))
    elif isinstance(password, bytes):
        return bytearray(password)
    elif isinstance(password, bytearray):
        # Create a COPY to avoid zeroing the original
        return bytearray(password)
    else:
        raise TypeError(f"Password must be str, bytes, or bytearray, got {type(password)}")


def _handle_error(e: Exception) -> Exception:
    """Convert Rust exceptions to Python exceptions"""
    msg = str(e)
    
    if "Authentication error" in msg or "Invalid password" in msg:
        return AuthenticationError(msg)
    elif "Integrity error" in msg or "Integrity hash mismatch" in msg:
        return IntegrityError(msg)
    else:
        return KrelError(msg)


# ============================================================================
# Async API (Base Implementation)
# ============================================================================

async def encrypt_async(
    source: str,
    destination: str,
    password: Union[str, bytes, bytearray]
) -> None:
    """
    Encrypt a file asynchronously.
    
    Args:
        source: Path to source file
        destination: Path to encrypted output file
        password: Password (str, bytes, or bytearray)
    
    Raises:
        KrelError: If encryption fails
    
    Example:
        await encrypt_async("secret.txt", "secret.txt.krel", "my-password")
    """
    engine = _KrelEngine()
    pwd_bytes = _to_bytearray(password)
    
    try:
        await engine.encrypt(source, destination, pwd_bytes)
    except Exception as e:
        raise _handle_error(e) from e


async def decrypt_async(
    source: str,
    destination: str,
    password: Union[str, bytes, bytearray]
) -> None:
    """
    Decrypt a file asynchronously.
    
    Args:
        source: Path to encrypted file
        destination: Path to decrypted output file
        password: Password (str, bytes, or bytearray)
    
    Raises:
        AuthenticationError: If password is wrong
        IntegrityError: If file is corrupted
        KrelError: If decryption fails
    
    Example:
        await decrypt_async("secret.txt.krel", "secret.txt", "my-password")
    """
    engine = _KrelEngine()
    pwd_bytes = _to_bytearray(password)
    
    try:
        await engine.decrypt(source, destination, pwd_bytes)
    except Exception as e:
        raise _handle_error(e) from e


async def rekey_async(
    path: str,
    old_password: Union[str, bytes, bytearray],
    new_password: Union[str, bytes, bytearray]
) -> None:
    """
    Change password for encrypted file (O(1) operation).
    
    Args:
        path: Path to encrypted file
        old_password: Current password
        new_password: New password
    
    Raises:
        AuthenticationError: If old password is wrong
        KrelError: If rekey fails
    
    Example:
        await rekey_async("secret.txt.krel", "old-pass", "new-pass")
    """
    engine = _KrelEngine()
    old_pwd = _to_bytearray(old_password)
    new_pwd = _to_bytearray(new_password)
    
    try:
        await engine.rekey(path, old_pwd, new_pwd)
    except Exception as e:
        raise _handle_error(e) from e


async def verify_async(path: str) -> bool:
    """
    Verify file integrity (fast, no password required).
    
    Args:
        path: Path to encrypted file
    
    Returns:
        True if file integrity is valid, False otherwise
    
    Example:
        is_valid = await verify_async("secret.txt.krel")
    """
    engine = _KrelEngine()
    
    try:
        return await engine.verify(path)
    except Exception as e:
        raise _handle_error(e) from e


async def verify_password_async(
    path: str,
    password: Union[str, bytes, bytearray]
) -> bool:
    """
    Verify password and file integrity (deep check).
    
    Args:
        path: Path to encrypted file
        password: Password to verify
    
    Returns:
        True if password is correct and file is valid, False otherwise
    
    Example:
        is_correct = await verify_password_async("secret.txt.krel", "my-password")
    """
    engine = _KrelEngine()
    pwd_bytes = _to_bytearray(password)
    
    try:
        return await engine.verify_full(path, pwd_bytes)
    except Exception as e:
        raise _handle_error(e) from e


# ============================================================================
# Sync API (Convenience Wrappers)
# ============================================================================

def _make_sync(async_func):
    """Convert async function to sync using asyncio.run"""
    @wraps(async_func)
    def wrapper(*args, **kwargs):
        return asyncio.run(async_func(*args, **kwargs))
    
    # Copy docstring and update it
    wrapper.__doc__ = async_func.__doc__
    if wrapper.__doc__:
        wrapper.__doc__ = wrapper.__doc__.replace("asynchronously", "synchronously")
        wrapper.__doc__ = wrapper.__doc__.replace("await ", "")
    
    return wrapper


# Create sync versions of all async functions
encrypt = _make_sync(encrypt_async)
decrypt = _make_sync(decrypt_async)
rekey = _make_sync(rekey_async)
verify = _make_sync(verify_async)
verify_password = _make_sync(verify_password_async)


# Update sync function names in docstrings
encrypt.__name__ = "encrypt"
decrypt.__name__ = "decrypt"
rekey.__name__ = "rekey"
verify.__name__ = "verify"
verify_password.__name__ = "verify_password"
