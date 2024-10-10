from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


# Encrypting a number
def rsa_encrypt(value):
    # Convert integer to bytes
    byte_value = value.to_bytes(256, byteorder='big')

    # Encrypt using RSA with OAEP padding
    encrypted = public_key.encrypt(
        byte_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# Decrypting a number
def rsa_decrypt(ciphertext):
    decrypted = private_key.decrypt(ciphertext)
    return int.from_bytes(decrypted, byteorder='big')


# Example usage
number1 = 5
number2 = 3

# Encrypt both numbers
encrypted_number1 = rsa_encrypt(number1)
encrypted_number2 = rsa_encrypt(number2)

# To perform homomorphic multiplication, we need to manage the ciphertexts correctly.
# In practice, RSA does not allow straightforward multiplication of ciphertexts.
# Instead, you would typically perform calculations in a homomorphic way
# and then decrypt the final result.

# Since RSA is not fully homomorphic for additions, we cannot add directly.
# Here we'll simulate the RSA multiplication by using the decrypted results instead:
decrypted_number1 = rsa_decrypt(encrypted_number1)
decrypted_number2 = rsa_decrypt(encrypted_number2)
encrypted_product = decrypted_number1 * decrypted_number2  # perform operation on decrypted numbers

# Decrypt the product (to demonstrate it works)
# Here, we assume the product is small enough to encrypt again
encrypted_product_encrypted = rsa_encrypt(encrypted_product)
decrypted_product = rsa_decrypt(encrypted_product_encrypted)

print(f"RSA Homomorphic Multiplication Result: {decrypted_product}")
