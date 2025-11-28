"""
Async API example for large files
"""

import asyncio
from krel import encrypt_async, decrypt_async, verify_password_async

async def main():
    # Create a test file
    print("Creating test file...")
    with open("large_file.bin", "wb") as f:
        # Create a 10 MB file
        f.write(b"x" * (10 * 1024 * 1024))
    
    # Encrypt asynchronously
    print("Encrypting...")
    await encrypt_async("large_file.bin", "large_file.bin.krel", "password")
    print("✓ Encrypted")
    
    # Verify password
    print("Verifying password...")
    is_valid = await verify_password_async("large_file.bin.krel", "password")
    print(f"✓ Password valid: {is_valid}")
    
    # Decrypt asynchronously
    print("Decrypting...")
    await decrypt_async("large_file.bin.krel", "large_file_decrypted.bin", "password")
    print("✓ Decrypted")
    
    # Verify files match
    with open("large_file.bin", "rb") as f1, open("large_file_decrypted.bin", "rb") as f2:
        assert f1.read() == f2.read()
    print("✓ Files match")
    
    # Cleanup
    import os
    os.remove("large_file.bin")
    os.remove("large_file.bin.krel")
    os.remove("large_file_decrypted.bin")
    
    print("\n✓ Async operations completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())
