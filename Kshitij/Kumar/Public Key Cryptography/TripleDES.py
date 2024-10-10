from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    """Generate a random 192-bit key for Triple DES."""
    return os.urandom(24)  # 192 bits = 24 bytes

def triple_des_encrypt(key, plaintext):
    """Encrypt the plaintext using Triple DES."""
    cipher = DES3.new(key, DES3.MODE_CBC)  # Create a new Triple DES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))  # Pad and encrypt
    return cipher.iv, ciphertext  # Return the initialization vector and ciphertext

def triple_des_decrypt(key, iv, ciphertext):
    """Decrypt the ciphertext using Triple DES."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # Create a new Triple DES cipher with the given IV
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)  # Decrypt and unpad
    return plaintext.decode()  # Return the plaintext as a string

# Example Usage
if __name__ == "__main__":
    # Take user input for the plaintext
    plaintext = input("Enter the plaintext to encrypt: ")

    # Generate a random Triple DES key
    key = generate_key()
    print(f"Generated Triple DES Key (hex): {key.hex()}")

    # Encrypt the plaintext
    iv, ciphertext = triple_des_encrypt(key, plaintext)
    print(f"Initialization Vector (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Decrypt the ciphertext
    decrypted_plaintext = triple_des_decrypt(key, iv, ciphertext)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")
