import python_paillier as paillier

# Generate Paillier keys
public_key, private_key = paillier.generate_paillier_keypair()

# Encrypting a number
def paillier_encrypt(value):
    return public_key.encrypt(value)

# Decrypting a number
def paillier_decrypt(ciphertext):
    return private_key.decrypt(ciphertext)

# Example usage
number3 = 5
number4 = 3

# Encrypt both numbers
encrypted_number3 = paillier_encrypt(number3)
encrypted_number4 = paillier_encrypt(number4)

# Homomorphic addition
encrypted_sum = encrypted_number3 + encrypted_number4

# Decrypt the sum
decrypted_sum = paillier_decrypt(encrypted_sum)

print(f"Paillier Homomorphic Addition Result: {decrypted_sum}")
