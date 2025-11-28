"""
Error handling example
"""

from krel import encrypt, decrypt, AuthenticationError, IntegrityError

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
    f.seek(100)
    f.write(b"\x00" * 10)  # Corrupt some bytes

try:
    decrypt("test.txt.krel", "output.txt", "correct-password")
except IntegrityError as e:
    print(f"✓ Caught IntegrityError: {e}")

# Example 3: File doesn't exist
print("\nExample 3: File doesn't exist")
try:
    decrypt("nonexistent.krel", "output.txt", "password")
except Exception as e:
    print(f"✓ Caught error: {type(e).__name__}")

# Cleanup
import os
os.remove("test.txt")
os.remove("test.txt.krel")
if os.path.exists("output.txt"):
    os.remove("output.txt")

print("\n✓ All error cases handled correctly!")
