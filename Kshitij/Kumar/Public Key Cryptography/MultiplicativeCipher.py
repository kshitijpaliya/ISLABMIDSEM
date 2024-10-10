def gcd(a, b):
    """Calculate GCD of a and b."""
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_cipher(plaintext, key):
    """Encrypt using Multiplicative Cipher."""
    ciphertext = ''.join(chr((ord(char) * key - 65) % 26 + 65) if char.isupper() else
                         chr((ord(char) * key - 97) % 26 + 97) if char.islower() else char
                         for char in plaintext)
    return ciphertext


def multiplicative_decrypt(ciphertext, key):
    """Decrypt using Multiplicative Cipher."""
    key_inverse = pow(key, -1, 26)  # Calculate modular inverse of key
    plaintext = ''.join(chr((ord(char) * key_inverse - 65) % 26 + 65) if char.isupper() else
                        chr((ord(char) * key_inverse - 97) % 26 + 97) if char.islower() else char
                        for char in ciphertext)
    return plaintext


# Example Usage
if __name__ == "__main__":
    plaintext = input("Enter plaintext for Multiplicative Cipher: ")
    key = int(input("Enter key (must be coprime with 26): "))

    if gcd(key, 26) != 1:
        print("Key must be coprime with 26!")
    else:
        encrypted = multiplicative_cipher(plaintext, key)
        print(f"Encrypted text: {encrypted}")

        decrypted = multiplicative_decrypt(encrypted, key)
        print(f"Decrypted text: {decrypted}")
