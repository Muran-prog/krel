"""
Password change (rekey) example
"""

from krel import encrypt, rekey, verify_password

# Create and encrypt a file
with open("secret.txt", "w") as f:
    f.write("Confidential data")

encrypt("secret.txt", "secret.txt.krel", "old-password")
print("✓ File encrypted with 'old-password'")

# Verify old password works
assert verify_password("secret.txt.krel", "old-password") == True
print("✓ Old password verified")

# Change password instantly (no re-encryption!)
rekey("secret.txt.krel", "old-password", "new-password")
print("✓ Password changed to 'new-password'")

# Old password no longer works
assert verify_password("secret.txt.krel", "old-password") == False
print("✓ Old password rejected")

# New password works
assert verify_password("secret.txt.krel", "new-password") == True
print("✓ New password verified")

# Cleanup
import os
os.remove("secret.txt")
os.remove("secret.txt.krel")

print("\n✓ Rekey completed successfully!")
