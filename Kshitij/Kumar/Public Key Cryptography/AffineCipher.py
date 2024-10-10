def gcd(a, b):
    """Calculate GCD of a and b."""
    while b != 0:
        a, b = b, a % b
    return a

def affine_cipher(plaintext, a, b):
    """Encrypt using Affine Cipher."""
    ciphertext = ''.join(chr((a * (ord(char) - 65) + b) % 26 + 65) if char.isupper() else
                         chr((a * (ord(char) - 97) + b) % 26 + 97) if char.islower() else char
                         for char in plaintext)
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    """Decrypt using Affine Cipher."""
    a_inverse = pow(a, -1, 26)  # Calculate modular inverse of a
    plaintext = ''.join(chr((a_inverse * (ord(char) - 65 - b)) % 26 + 65) if char.isupper() else
                         chr((a_inverse * (ord(char) - 97 - b)) % 26 + 97) if char.islower() else char
                         for char in ciphertext)
    return plaintext

# Example Usage
if __name__ == "__main__":
    plaintext = input("Enter plaintext for Affine Cipher: ")
    a = int(input("Enter a (must be coprime with 26): "))
    b = int(input("Enter b: "))

    if gcd(a, 26) != 1:
        print("Error: 'a' must be coprime with 26!")
    else:
        encrypted = affine_cipher(plaintext, a, b)
        print(f"Encrypted text: {encrypted}")

        decrypted = affine_decrypt(encrypted, a, b)
        print(f"Decrypted text: {decrypted}")
