"""
Basic encryption and decryption example
"""

from krel import encrypt, decrypt

# Create a test file
with open("document.txt", "w") as f:
    f.write("This is a secret document.")

# Encrypt the file
encrypt("document.txt", "document.txt.krel", "my-secure-password")
print("✓ File encrypted")

# Decrypt the file
decrypt("document.txt.krel", "document_decrypted.txt", "my-secure-password")
print("✓ File decrypted")

# Verify content
with open("document_decrypted.txt", "r") as f:
    content = f.read()
    print(f"Content: {content}")

# Cleanup
import os
os.remove("document.txt")
os.remove("document.txt.krel")
os.remove("document_decrypted.txt")
