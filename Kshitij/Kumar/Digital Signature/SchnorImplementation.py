from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Util import number


# Step 1: Key Generation (Schnorr uses group parameters p, q, g)
def generate_schnorr_keys(bits=256):
    # Generate large prime p and q such that q divides p-1
    q = number.getPrime(bits)
    p = 2 * q + 1

    # Select generator g of order q
    g = pow(2, (p - 1) // q, p)

    # Private key is a random number x such that 1 <= x < q
    private_key = random.randint(1, q - 1)

    # Public key y = g^x mod p
    public_key = pow(g, private_key, p)

    return p, q, g, private_key, public_key


# Step 2: Signing the message
def schnorr_sign(message, p, q, g, private_key):
    # Hash the message
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')

    # Generate random nonce k such that 1 <= k < q
    k = random.randint(1, q - 1)

    # Compute r = g^k mod p
    r = pow(g, k, p)

    # Compute e = H(r || message) mod q
    hash_e = SHA256.new((str(r) + message).encode())
    e = int.from_bytes(hash_e.digest(), byteorder='big') % q

    # Compute s = (k - e * private_key) mod q
    s = (k - e * private_key) % q

    return r, s


# Step 3: Verify the Schnorr signature
def schnorr_verify(message, r, s, p, q, g, public_key):
    # Compute e = H(r || message) mod q
    hash_e = SHA256.new((str(r) + message).encode())
    e = int.from_bytes(hash_e.digest(), byteorder='big') % q

    # Compute v = (g^s * y^e) mod p
    v = (pow(g, s, p) * pow(public_key, e, p)) % p

    # The signature is valid if v == r
    return v == r


# Main Execution: Key Generation, Signing, and Verification
if __name__ == "__main__":
    # Step 1: Generate keys
    p, q, g, private_key, public_key = generate_schnorr_keys()

    print("Schnorr Public Parameters (p, q, g):")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    print("\nPrivate Key (x):")
    print(f"x = {private_key}")

    print("\nPublic Key (y):")
    print(f"y = {public_key}")

    # Step 2: Sign a message
    message = "Hello, Schnorr Digital Signatures!"
    r, s = schnorr_sign(message, p, q, g, private_key)
    print(f"\nSignature (r, s): ({r}, {s})")

    # Step 3: Verify the signature
    is_valid = schnorr_verify(message, r, s, p, q, g, public_key)
    print("\nIs the signature valid?:", is_valid)
