from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    """Generate a random 56-bit key for DES."""
    return os.urandom(8)  # DES key is 64 bits, but 8 bits are used for parity

def des_encrypt(key, plaintext):
    """Encrypt the plaintext using DES."""
    cipher = DES.new(key, DES.MODE_CBC)  # Create a new DES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(plaintext.encode(), DES.block_size))  # Pad and encrypt
    return cipher.iv, ciphertext  # Return the initialization vector and ciphertext

def des_decrypt(key, iv, ciphertext):
    """Decrypt the ciphertext using DES."""
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Create a new DES cipher with the given IV
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)  # Decrypt and unpad
    return plaintext.decode()  # Return the plaintext as a string

# Example Usage
if __name__ == "__main__":
    # Take user input for the plaintext
    plaintext = input("Enter the plaintext to encrypt: ")

    # Generate a random DES key
    key = generate_key()
    print(f"Generated DES Key (hex): {key.hex()}")

    # Encrypt the plaintext
    iv, ciphertext = des_encrypt(key, plaintext)
    print(f"Initialization Vector (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Decrypt the ciphertext
    decrypted_plaintext = des_decrypt(key, iv, ciphertext)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")
