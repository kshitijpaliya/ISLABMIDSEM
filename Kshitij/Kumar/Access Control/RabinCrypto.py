import random
from sympy import isprime


def generate_large_prime(bits):
    """Generate a random prime number with the specified bit length."""
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num


def generate_keys(bits=1024):
    """Generate Rabin public and private keys."""
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)

    n = p * q  # Public key
    private_keys = (p, q)  # Private keys
    return (n, private_keys)


def rabin_encrypt(message, n):
    """Encrypt the message using the Rabin public key."""
    # Convert the message to an integer
    m = int.from_bytes(message.encode(), 'big')

    # Ensure m < n
    if m >= n:
        raise ValueError("Message is too long for the given key.")

    # Compute ciphertext c = m^2 mod n
    c = pow(m, 2, n)
    return c


def rabin_decrypt(c, private_keys):
    """Decrypt the ciphertext using the Rabin private keys."""
    p, q = private_keys

    # Compute the modular square roots
    root1 = pow(c, (p + 1) // 4, p)
    root2 = (p - root1) % p
    root3 = pow(c, (q + 1) // 4, q)
    root4 = (q - root3) % q

    # Use the Chinese Remainder Theorem to combine roots
    m1 = chinese_remainder(root1, p, root3, q)
    m2 = chinese_remainder(root1, p, root4, q)
    m3 = chinese_remainder(root2, p, root3, q)
    m4 = chinese_remainder(root2, p, root4, q)

    return [m1, m2, m3, m4]


def chinese_remainder(a1, p, a2, q):
    """Solve the system of congruences using the Chinese Remainder Theorem."""
    M = p * q
    M1 = M // p
    M2 = M // q

    # Find multiplicative inverses
    inv1 = pow(M1, -1, p)
    inv2 = pow(M2, -1, q)

    # Combine the solutions
    x = (a1 * M1 * inv1 + a2 * M2 * inv2) % M
    return x


def is_valid_utf8(byte_array):
    """Check if a byte array can be decoded as valid UTF-8."""
    try:
        byte_array.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


# Example Usage
if __name__ == "__main__":
    # Take user input for key size
    bits = int(input("Enter the key size in bits (e.g., 512, 1024): "))
    public_key, private_keys = generate_keys(bits)
    print(f"Public Key (n): {public_key}")

    # Take user input for the message
    message = input("Enter the message to encrypt: ")
    print(f"Original Message: {message}")

    # Encrypt the message
    ciphertext = rabin_encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_candidates = rabin_decrypt(ciphertext, private_keys)

    # Convert decrypted candidates back to string
    decrypted_messages = []
    for candidate in decrypted_candidates:
        byte_length = (candidate.bit_length() + 7) // 8
        decrypted_message_bytes = candidate.to_bytes(byte_length, 'big')

        if is_valid_utf8(decrypted_message_bytes):
            decrypted_messages.append(decrypted_message_bytes.decode('utf-8'))
        else:
            decrypted_messages.append("Invalid character sequence")

    print("Decrypted Messages:", decrypted_messages)
