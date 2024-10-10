def autokey_encrypt(plaintext, keyword):
    """Encrypt using Autokey Cipher."""
    keyword = keyword.upper()
    plaintext = plaintext.upper().replace(" ", "")
    key = keyword + plaintext  # Extend the key with the plaintext
    ciphertext = ''

    for i in range(len(plaintext)):
        # Calculate the shift for each character
        shift = (ord(key[i]) - 65) % 26
        # Encrypt character
        cipher_char = chr((ord(plaintext[i]) - 65 + shift) % 26 + 65)
        ciphertext += cipher_char

    return ciphertext


def autokey_decrypt(ciphertext, keyword):
    """Decrypt using Autokey Cipher."""
    keyword = keyword.upper()
    ciphertext = ciphertext.upper().replace(" ", "")
    plaintext = ''
    key = list(keyword)

    for i in range(len(ciphertext)):
        # Calculate the shift for each character
        shift = (ord(key[i]) - 65) % 26
        # Decrypt character
        plain_char = chr((ord(ciphertext[i]) - 65 - shift) % 26 + 65)
        plaintext += plain_char

        # Update the key with the decrypted character
        key.append(plain_char)

    return plaintext


# Example Usage
if __name__ == "__main__":
    plaintext = input("Enter plaintext for Autokey Cipher: ")
    keyword = input("Enter keyword: ")

    encrypted = autokey_encrypt(plaintext, keyword)
    print(f"Encrypted text: {encrypted}")

    decrypted = autokey_decrypt(encrypted, keyword)
    print(f"Decrypted text: {decrypted}")
