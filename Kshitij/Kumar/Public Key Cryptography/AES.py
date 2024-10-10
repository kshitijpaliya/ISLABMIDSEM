from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def generate_key(key_size):
    """Generate a random AES key of the specified size (128, 192, or 256 bits)."""
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits.")
    return os.urandom(key_size // 8)  # Convert bits to bytes


def aes_encrypt(key, plaintext):
    """Encrypt the plaintext using AES."""
    cipher = AES.new(key, AES.MODE_CBC)  # Create a new AES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))  # Pad and encrypt
    return cipher.iv, ciphertext  # Return the initialization vector and ciphertext


def aes_decrypt(key, iv, ciphertext):
    """Decrypt the ciphertext using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create a new AES cipher with the given IV
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt and unpad
    return plaintext.decode()  # Return the plaintext as a string


# Example Usage
if __name__ == "__main__":
    # Take user input for the plaintext
    plaintext = input("Enter the plaintext to encrypt: ")

    # Take user input for key size
    key_size = int(input("Enter the key size (128, 192, or 256 bits): "))

    # Generate a random AES key
    key = generate_key(key_size)
    print(f"Generated AES Key (hex): {key.hex()}")

    # Encrypt the plaintext
    iv, ciphertext = aes_encrypt(key, plaintext)
    print(f"Initialization Vector (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Decrypt the ciphertext
    decrypted_plaintext = aes_decrypt(key, iv, ciphertext)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")
