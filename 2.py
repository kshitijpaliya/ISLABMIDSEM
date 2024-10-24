import random
import sympy
from sympy import mod_inverse
import hashlib

# Helper function for the Paillier cryptosystem
def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if sympy.isprime(p):
            return p

def L(u, n):
    """ L(u) = (u - 1) / n used in the decryption step of Paillier """
    return (u - 1) // n

def genkeypair():
    """ Generate Paillier public and private keys """
    p = genprime()
    q = genprime()
    n = p * q
    lam = sympy.lcm(p - 1, q - 1)
    g = random.randint(1, n * n)

    lam = int(lam)
    mu = mod_inverse(L(pow(g, lam, n * n), n), n)

    return (n, g), (lam, mu)

def encrypt(pubk, msg):
    """ Paillier encryption """
    n, g = pubk
    while True:
        r = random.randint(1, n - 1)
        if sympy.gcd(r, n) == 1:
            break
    c = (pow(g, msg, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def decrypt(prik, ct, pubk):
    """ Paillier decryption """
    n, _ = pubk
    lam, mu = prik
    msg = (L(pow(ct, lam, n * n), n) * mu) % n
    return msg

def homadd(c1, c2, pubk):
    """ Paillier homomorphic addition of two ciphertexts """
    n, _ = pubk
    return (c1 * c2) % (n * n)

# Helper functions for RSA-based Digital Signatures
def hash_message(message):
    """ Hash the message using SHA-256. """
    hasher = hashlib.sha256()
    hasher.update(message.encode())
    return int(hasher.hexdigest(), 16)

def rsa_genkeypair(bits=16):
    """ Generate RSA public and private key pair. """
    p = genprime(bits)
    q = genprime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = random.randint(2, phi_n - 1)
    while sympy.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)
    return (n, e), (n, d)  # Public key (n, e) and private key (n, d)

def rsa_sign(privkey, message):
    """ Create a digital signature by signing the hash of the message using RSA. """
    message_hash = hash_message(message)
    n, d = privkey
    signature = pow(message_hash, d, n)  # Sign the hash using private key
    return signature

def rsa_verify(pubkey, message, signature):
    """ Verify the RSA digital signature using the public key. """
    message_hash = hash_message(message)
    n, e = pubkey
    decrypted_hash = pow(signature, e, n)  # Decrypt signature using public key
    return message_hash == decrypted_hash

# Example usage
if __name__ == "__main__":
    # Paillier Encryption
    num1 = 17
    num2 = 20

    pubk, prik = genkeypair()

    # Encrypt the numbers
    c1 = encrypt(pubk, num1)
    c2 = encrypt(pubk, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    # Perform homomorphic addition
    c = homadd(c1, c2, pubk)
    print(f"Encrypted sum: {c}")

    # Decrypt the result
    dec = decrypt(prik, c, pubk)
    print(f"Decrypted sum: {dec}")
    print(f"Original sum: {num1 + num2}\n")

    # RSA Digital Signature
    message = "This is a test message."

    # Generate RSA key pair
    rsa_pubkey, rsa_privkey = rsa_genkeypair()

    # Sign the message
    signature = rsa_sign(rsa_privkey, message)
    print(f"Signature: {signature}")

    # Verify the signature
    is_valid = rsa_verify(rsa_pubkey, message, signature)
    print(f"Signature valid: {is_valid}")
