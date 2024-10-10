import random

def generate_prime_and_generator():
    # In a real implementation, you would choose a large prime number and generator
    p = 23  # A small prime for demonstration
    g = 5   # A primitive root modulo p
    return p, g

def generate_private_key():
    # Generate a private key (random number)
    return random.randint(1, 20)

def calculate_public_key(p, g, private_key):
    # Public key is g^private_key mod p
    return pow(g, private_key, p)

def calculate_shared_secret(p, public_key_other, private_key):
    # Shared secret is public_key_other^private_key mod p
    return pow(public_key_other, private_key, p)

# Main execution
if __name__ == "__main__":
    # Step 1: Generate prime number and generator
    p, g = generate_prime_and_generator()
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")

    # Step 2: Each party generates their private key
    private_key_A = generate_private_key()
    private_key_B = generate_private_key()
    print(f"Private key A: {private_key_A}")
    print(f"Private key B: {private_key_B}")

    # Step 3: Each party calculates their public key
    public_key_A = calculate_public_key(p, g, private_key_A)
    public_key_B = calculate_public_key(p, g, private_key_B)
    print(f"Public key A: {public_key_A}")
    print(f"Public key B: {public_key_B}")

    # Step 4: Each party calculates the shared secret
    shared_secret_A = calculate_shared_secret(p, public_key_B, private_key_A)
    shared_secret_B = calculate_shared_secret(p, public_key_A, private_key_B)

    # Step 5: Verify that both parties have the same shared secret
    print(f"Shared secret calculated by A: {shared_secret_A}")
    print(f"Shared secret calculated by B: {shared_secret_B}")

    if shared_secret_A == shared_secret_B:
        print("Shared secret matches. Key exchange successful!")
    else:
        print("Shared secret does not match. Key exchange failed.")
