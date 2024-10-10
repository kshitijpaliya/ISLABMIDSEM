def additive_cipher(plaintext, key):
    """Encrypt using Additive Cipher."""
    ciphertext = ''.join(chr((ord(char) + key - 65) % 26 + 65) if char.isupper() else
                         chr((ord(char) + key - 97) % 26 + 97) if char.islower() else char
                         for char in plaintext)
    return ciphertext


def additive_decrypt(ciphertext, key):
    """Decrypt using Additive Cipher."""
    plaintext = ''.join(chr((ord(char) - key - 65) % 26 + 65) if char.isupper() else
                        chr((ord(char) - key - 97) % 26 + 97) if char.islower() else char
                        for char in ciphertext)
    return plaintext


# Example Usage
if __name__ == "__main__":
    plaintext = input("Enter plaintext for Additive Cipher: ")
    key = int(input("Enter key (shift value): "))

    encrypted = additive_cipher(plaintext, key)
    print(f"Encrypted text: {encrypted}")

    decrypted = additive_decrypt(encrypted, key)
    print(f"Decrypted text: {decrypted}")
