# hashing.py

from cryptography.hazmat.primitives import hashes

def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()
