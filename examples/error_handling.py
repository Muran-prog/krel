"""
Error handling example
"""

from krel import encrypt, decrypt, AuthenticationError, IntegrityError, KrelError

# Create a test file
with open("test.txt", "w") as f:
    f.write("Test data")

encrypt("test.txt", "test.txt.krel", "correct-password")

# Example 1: Wrong password
print("Example 1: Wrong password")
try:
    decrypt("test.txt.krel", "output.txt", "wrong-password")
except AuthenticationError as e:
    print(f"✓ Caught AuthenticationError: {e}")

# Example 2: Corrupted file
print("\nExample 2: Corrupted file")
with open("test.txt.krel", "r+b") as f:
    # Header is 128 bytes. If we modify < 128, we get AuthError.
    # If we modify > 128, we usually get IntegrityError.
    f.seek(100) 
    f.write(b"\x00" * 10)  # Corrupt some bytes

try:
    decrypt("test.txt.krel", "output.txt", "correct-password")
except (IntegrityError, AuthenticationError) as e:
    print(f"✓ Caught expected error: {e}")
except Exception as e:
    print(f"X Caught unexpected error: {type(e).__name__}: {e}")
    exit(1)

# Example 3: File doesn't exist
print("\nExample 3: File doesn't exist")
try:
    decrypt("nonexistent.krel", "output.txt", "password")
except Exception as e:
    print(f"✓ Caught error: {type(e).__name__}")

# Cleanup
import os
if os.path.exists("test.txt"): os.remove("test.txt")
if os.path.exists("test.txt.krel"): os.remove("test.txt.krel")
if os.path.exists("output.txt"): os.remove("output.txt")

print("\n✓ All error cases handled correctly!")