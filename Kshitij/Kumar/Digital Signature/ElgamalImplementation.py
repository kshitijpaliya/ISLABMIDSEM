from Crypto.Util import number
from Crypto.Hash import SHA256
import random


# Step 1: Generate ElGamal Keys (p, g, private_key, public_key)
def generate_elgamal_keys(bits=2048):
    # Generate a large prime number 'p'
    p = number.getPrime(bits)

    # Select a generator 'g'
    g = random.randint(2, p - 1)

    # Private key (x) is a random number in the range [1, p-2]
    private_key = random.randint(1, p - 2)

    # Public key (y = g^x mod p)
    public_key = pow(g, private_key, p)

    return p, g, private_key, public_key


# Step 2: Sign a message using the ElGamal algorithm
def elgamal_sign(message, p, g, private_key):
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')

    # Choose a random 'k' such that 1 <= k <= p-2 and gcd(k, p-1) = 1
    k = random.randint(1, p - 2)
    while number.GCD(k, p - 1) != 1:
        k = random.randint(1, p - 2)

    # Compute r = g^k mod p
    r = pow(g, k, p)

    # Compute the modular inverse of k (k^-1 mod (p-1))
    k_inv = number.inverse(k, p - 1)

    # Compute s = (k^-1 * (h - private_key * r)) mod (p-1)
    s = (k_inv * (h - private_key * r)) % (p - 1)

    return r, s


# Step 3: Verify the ElGamal signature
def elgamal_verify(message, r, s, p, g, public_key):
    # Check if 'r' is within the valid range
    if r <= 0 or r >= p:
        return False

    # Hash the message again using SHA-256
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')

    # Verify the signature: g^h mod p == (r^s * public_key^r) mod p
    lhs = pow(g, h, p)
    rhs = (pow(r, s, p) * pow(public_key, r, p)) % p

    # Signature is valid if both sides are equal
    return lhs == rhs


# Main Execution: Key Generation, Signing, and Verification
if __name__ == "__main__":
    # Generate keys
    p, g, private_key, public_key = generate_elgamal_keys()

    # Display generated keys
    print("Public Parameters (p, g):")
    print(f"p = {p}")
    print(f"g = {g}")

    print("\nPrivate Key:")
    print(f"x = {private_key}")

    print("\nPublic Key:")
    print(f"y = {public_key}")

    # Sample message to sign
    message = "Hello, ElGamal Digital Signatures!"

    # Sign the message
    r, s = elgamal_sign(message, p, g, private_key)
    print(f"\nSignature (r, s): ({r}, {s})")

    # Verify the signature
    is_valid = elgamal_verify(message, r, s, p, g, public_key)
    print("\nIs the signature valid?:", is_valid)
