import random
import sympy
from sympy import mod_inverse, isprime
import hashlib

def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def genkeypair(bits=16):
    """ Generate RSA public and private key pair. """
    p = genprime(bits)
    q = genprime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(2, phi_n - 1)
    while sympy.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)

    return (n, e), (n, d)  # Public key (n, e) and private key (n, d)

def encrypt(pubkey, plaintext):
    """ Encrypt a plaintext message using the public key. """
    n, e = pubkey
    return pow(plaintext, e, n)

def decrypt(privkey, ciphertext):
    """ Decrypt a ciphertext message using the private key. """
    n, d = privkey
    return pow(ciphertext, d, n)

def homomorphic_multiply(c1, c2, n):
    """ Multiply two ciphertexts under RSA encryption. """
    return (c1 * c2) % n

def hash_message(message):
    """ Hash the message using SHA-256. """
    hasher = hashlib.sha256()
    hasher.update(message.encode())
    return int(hasher.hexdigest(), 16)

def sign_message(privkey, message):
    """ Create a digital signature by signing the hash of the message. """
    message_hash = hash_message(message)
    signature = decrypt(privkey, message_hash)  # Sign using private key
    return signature

def verify_signature(pubkey, message, signature):
    """ Verify the digital signature using the public key. """
    message_hash = hash_message(message)
    decrypted_hash = encrypt(pubkey, signature)  # Decrypt signature using public key
    return message_hash == decrypted_hash

# Example usage
if __name__ == "__main__":
    num1 = 7
    num2 = 3
    message = "This is a secret message."

    # Generate RSA key pair
    pubkey, privkey = genkeypair()

    print(f"Public key: {pubkey}")
    print(f"Private key: {privkey}\n")

    # Encrypt the numbers
    c1 = encrypt(pubkey, num1)
    c2 = encrypt(pubkey, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    # Perform homomorphic multiplication
    c_product = homomorphic_multiply(c1, c2, pubkey[0])
    print(f"Encrypted product: {c_product}")

    # Decrypt the result
    dec_product = decrypt(privkey, c_product)
    print(f"Decrypted product: {dec_product}")
    print(f"Original product: {num1 * num2}\n")

    # Digital Signature
    print(f"Original message: {message}")
    signature = sign_message(privkey, message)
    print(f"Signature: {signature}")

    # Verify the signature
    is_valid = verify_signature(pubkey, message, signature)
    print(f"Signature valid: {is_valid}")
