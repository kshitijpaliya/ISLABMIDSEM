import hashlib
import time
import random
import string
from collections import defaultdict


# Function to generate a random string
def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# Function to compute hash values
def compute_hashes(data, hash_func):
    hash_dict = {}
    for item in data:
        hash_value = hash_func(item.encode()).hexdigest()
        hash_dict[item] = hash_value
    return hash_dict


# Function to detect collisions
def detect_collisions(hash_dict):
    inverse_hash = defaultdict(list)
    collisions = []

    for item, hash_value in hash_dict.items():
        inverse_hash[hash_value].append(item)

    for hash_value, items in inverse_hash.items():
        if len(items) > 1:
            collisions.append((hash_value, items))

    return collisions


# Main experiment function
def run_experiment(num_strings=100, min_length=10, max_length=20):
    # Generate random dataset
    dataset = [generate_random_string(random.randint(min_length, max_length)) for _ in range(num_strings)]

    # Measure time for MD5
    start_time = time.time()
    md5_hashes = compute_hashes(dataset, hashlib.md5)
    md5_time = time.time() - start_time

    # Measure time for SHA-1
    start_time = time.time()
    sha1_hashes = compute_hashes(dataset, hashlib.sha1)
    sha1_time = time.time() - start_time

    # Measure time for SHA-256
    start_time = time.time()
    sha256_hashes = compute_hashes(dataset, hashlib.sha256)
    sha256_time = time.time() - start_time

    # Detect collisions
    md5_collisions = detect_collisions(md5_hashes)
    sha1_collisions = detect_collisions(sha1_hashes)
    sha256_collisions = detect_collisions(sha256_hashes)

    # Print results
    print(f"MD5 computation time: {md5_time:.4f} seconds")
    print(f"SHA-1 computation time: {sha1_time:.4f} seconds")
    print(f"SHA-256 computation time: {sha256_time:.4f} seconds")

    print(f"MD5 collisions: {len(md5_collisions)}")
    print(f"SHA-1 collisions: {len(sha1_collisions)}")
    print(f"SHA-256 collisions: {len(sha256_collisions)}")

    # Print collisions for analysis
    if md5_collisions:
        print("\nMD5 Collisions:")
        for collision in md5_collisions:
            print(f"Hash: {collision[0]}")
            print(f"Strings: {collision[1]}")

    if sha1_collisions:
        print("\nSHA-1 Collisions:")
        for collision in sha1_collisions:
            print(f"Hash: {collision[0]}")
            print(f"Strings: {collision[1]}")

    if sha256_collisions:
        print("\nSHA-256 Collisions:")
        for collision in sha256_collisions:
            print(f"Hash: {collision[0]}")
            print(f"Strings: {collision[1]}")


if __name__ == "__main__":
    run_experiment()
