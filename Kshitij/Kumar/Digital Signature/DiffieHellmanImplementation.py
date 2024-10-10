from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Random import random


# Step 1: Key Generation (similar to Diffie-Hellman)
def generate_elgamal_keys(bits=256):
    # Generate large prime p and generator g
    p = number.getPrime(bits)
    g = random.randint(2, p - 2)

    # Private key is a random number x such that 1 <= x < p-1
    private_key = random.randint(1, p - 2)

    # Public key is y = g^x mod p
    public_key = pow(g, private_key, p)

    return p, g, private_key, public_key


# Step 2: Signing the message using ElGamal Signature Scheme
def elgamal_sign(message, p, g, private_key):
    # Hash the message
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')

    # Generate a random k such that 1 <= k <= p-2 and gcd(k, p-1) = 1
    while True:
        k = random.randint(1, p - 2)
        if number.GCD(k, p - 1) == 1:
            break

    # Compute r = g^k mod p
    r = pow(g, k, p)

    # Compute s = (h - private_key * r) * k^-1 mod (p - 1)
    k_inv = number.inverse(k, p - 1)
    s = (k_inv * (h - private_key * r)) % (p - 1)

    return r, s


# Step 3: Verify the ElGamal signature
def elgamal_verify(message, r, s, p, g, public_key):
    # Hash the message
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')

    # Compute v1 = (public_key^r * r^s) mod p
    v1 = (pow(public_key, r, p) * pow(r, s, p)) % p

    # Compute v2 = g^h mod p
    v2 = pow(g, h, p)

    # Signature is valid if v1 == v2
    return v1 == v2


# Main Execution: Key Generation, Signing, and Verification
if __name__ == "__main__":
    # Step 1: Generate keys
    p, g, private_key, public_key = generate_elgamal_keys()

    print("ElGamal Public Parameters (p, g):")
    print(f"p = {p}")
    print(f"g = {g}")

    print("\nPrivate Key (x):")
    print(f"x = {private_key}")

    print("\nPublic Key (y):")
    print(f"y = {public_key}")

    # Step 2: Sign a message
    message = "Hello, ElGamal Signatures!"
    r, s = elgamal_sign(message, p, g, private_key)
    print(f"\nSignature (r, s): ({r}, {s})")

    # Step 3: Verify the signature
    is_valid = elgamal_verify(message, r, s, p, g, public_key)
    print("\nIs the signature valid?:", is_valid)
