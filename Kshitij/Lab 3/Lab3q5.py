import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Generate DH parameters (these are typically shared between peers)
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


# Generate DH private and public keys for a peer
def generate_dh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


# Exchange and compute shared secret
def compute_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)

    # Derive a symmetric key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file transfer',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


# Measure the time taken for key generation and key exchange
def measure_performance():
    # Step 1: Generate DH parameters (this happens only once)
    start_time = time.time()
    dh_parameters = generate_dh_parameters()
    param_gen_time = time.time() - start_time

    # Step 2: Peer A generates its DH key pair
    start_time = time.time()
    private_key_A, public_key_A = generate_dh_key_pair(dh_parameters)
    key_gen_time_A = time.time() - start_time

    # Step 3: Peer B generates its DH key pair
    start_time = time.time()
    private_key_B, public_key_B = generate_dh_key_pair(dh_parameters)
    key_gen_time_B = time.time() - start_time

    # Step 4: Compute shared secret for both peers
    start_time = time.time()
    shared_secret_A = compute_shared_secret(private_key_A, public_key_B)
    shared_secret_B = compute_shared_secret(private_key_B, public_key_A)
    exchange_time = time.time() - start_time

    # Check if both shared secrets are identical (they should be)
    assert shared_secret_A == shared_secret_B, "Shared secrets do not match!"

    return param_gen_time, key_gen_time_A, key_gen_time_B, exchange_time


def main():
    param_gen_time, key_gen_time_A, key_gen_time_B, exchange_time = measure_performance()

    print(f"DH Parameter Generation Time: {param_gen_time:.6f} seconds")
    print(f"Peer A Key Generation Time: {key_gen_time_A:.6f} seconds")
    print(f"Peer B Key Generation Time: {key_gen_time_B:.6f} seconds")
    print(f"Key Exchange Time: {exchange_time:.6f} seconds")


if __name__ == "__main__":
    main()
