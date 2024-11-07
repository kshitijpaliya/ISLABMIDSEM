import random
from sympy import mod_inverse, isprime
import hashlib

def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def gen_elgamal_keypair(bits=16):
    """ Generate ElGamal public and private key pair. """
    p = genprime(bits)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)  # Private key x
    y = pow(g, x, p)  # Public key component y

    return (p, g, y), x  # Public key (p, g, y) and private key x

def elgamal_encrypt(pubkey, plaintext):
    """ Encrypt a plaintext message using the ElGamal public key. """
    p, g, y = pubkey
    k = random.randint(1, p - 2)  # Random ephemeral key
    c1 = pow(g, k, p)
    c2 = (plaintext * pow(y, k, p)) % p
    return c1, c2

def elgamal_decrypt(privkey, pubkey, ciphertext):
    """ Decrypt a ciphertext message using the ElGamal private key. """
    p, g, y = pubkey
    x = privkey
    c1, c2 = ciphertext
    s = pow(c1, x, p)  # Shared secret
    plaintext = (c2 * mod_inverse(s, p)) % p
    return plaintext

def elgamal_add_encrypted(c1, c2, p):
    """ Add two ciphertexts under ElGamal encryption. """
    return (c1[0] * c2[0] % p, c1[1] * c2[1] % p)

def hash_message(message):
    """ Hash the message using SHA-256. """
    hasher = hashlib.sha256()
    hasher.update(message.encode())
    return int(hasher.hexdigest(), 16)

def elgamal_sign(privkey, pubkey, message):
    """ Create a digital signature using ElGamal private key. """
    p, g, _ = pubkey
    x = privkey
    message_hash = hash_message(message)
    while True:
        k = random.randint(1, p - 2)
        if mod_inverse(k, p - 1) is not None:
            break
    r = pow(g, k, p)
    s = (mod_inverse(k, p - 1) * (message_hash - x * r)) % (p - 1)
    return r, s

def elgamal_verify_signature(pubkey, message, signature):
    """ Verify the ElGamal signature using the public key. """
    p, g, y = pubkey
    r, s = signature
    message_hash = hash_message(message)
    if not (0 < r < p):
        return False
    left = pow(y, r, p) * pow(r, s, p) % p
    right = pow(g, message_hash, p)
    return left == right

# Example usage
if __name__ == "__main__":
    num1 = 7
    num2 = 3
    message = "This is a secret message."

    # Generate ElGamal key pair
    pubkey, privkey = gen_elgamal_keypair()

    print(f"Public key: {pubkey}")
    print(f"Private key: {privkey}\n")

    # Encrypt the numbers
    c1 = elgamal_encrypt(pubkey, num1)
    c2 = elgamal_encrypt(pubkey, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    # Perform homomorphic addition
    c_sum = elgamal_add_encrypted(c1, c2, pubkey[0])
    print(f"Encrypted sum: {c_sum}")

    # Decrypt the result
    dec_sum = elgamal_decrypt(privkey, pubkey, c_sum)
    print(f"Decrypted sum: {dec_sum}")
    print(f"Original sum: {num1 + num2}\n")

    # Digital Signature
    print(f"Original message: {message}")
    signature = elgamal_sign(privkey, pubkey, message)
    print(f"Signature: {signature}")

    # Verify the signature
    is_valid = elgamal_verify_signature(pubkey, message, signature)
    print(f"Signature valid: {is_valid}")
