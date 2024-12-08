"""Generate a random 16-byte (128-bit) and 32-byte (256-bit) AES key"""
import os

# Generate a random 16-byte (128-bit) AES key
aes_key_128 = os.urandom(16)

# Or, generate a random 32-byte (256-bit) AES key
aes_key_256 = os.urandom(32)

# Print the key in hexadecimal format for readability
print(f"AES-128 key: {aes_key_128.hex()}")
print(f"AES-256 key: {aes_key_256.hex()}")
