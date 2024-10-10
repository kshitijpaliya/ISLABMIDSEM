import random


# Generate ElGamal keypair
def generate_elgamal_keypair(p, g):
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


# Encrypt using ElGamal
def elgamal_encrypt(p, g, public_key, message):
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)  # Compute c1
    c2 = (message * pow(public_key, y, p)) % p  # Compute c2
    return c1, c2


# Decrypt using ElGamal
def elgamal_decrypt(private_key, p, c1, c2):
    s = pow(c1, private_key, p)  # Shared secret
    decrypted_message = (c2 * pow(s, p - 2, p)) % p  # Decrypt message using modular inverse
    return decrypted_message


# Main execution
if __name__ == "__main__":
    # Take user input for prime number and generator
    p = int(input("Enter a prime number (p): "))
    g = int(input("Enter a generator (g): "))

    # Generate keypair
    private_key, public_key = generate_elgamal_keypair(p, g)

    # Take user input for message to encrypt
    message = int(input("Enter a message to encrypt (as an integer): "))

    # Encrypt the message
    c1, c2 = elgamal_encrypt(p, g, public_key, message)
    print("Encrypted message (c1, c2):", (c1, c2))

    # Decrypt the message
    decrypted = elgamal_decrypt(private_key, p, c1, c2)
    print("Decrypted message:", decrypted)

