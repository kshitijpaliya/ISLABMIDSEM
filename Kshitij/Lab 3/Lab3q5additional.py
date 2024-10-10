# import time
# import os
# from cryptography.hazmat.primitives.asymmetric import rsa, ec
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
# # from cryptography.hazmat.primitives.kdf.ecdh import ECDH

# # Helper function to generate a random message of a given size
# def generate_message(size_kb):
#     return os.urandom(size_kb * 1024)

# # Measure the time taken for RSA key generation, encryption, and decryption
# def rsa_performance(message):
#     print("\n--- RSA 2048-bit ---")

#     # RSA key generation
#     start_time = time.time()
#     private_key_rsa = rsa.generate_private_key(
#         public_exponent=65537, key_size=2048, backend=default_backend()
#     )
#     public_key_rsa = private_key_rsa.public_key()
#     keygen_time = time.time() - start_time
#     print(f"RSA Key Generation Time: {keygen_time:.6f} seconds")

#     # RSA encryption
#     start_time = time.time()
#     encrypted_message = public_key_rsa.encrypt(
#         message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     encryption_time = time.time() - start_time
#     print(f"RSA Encryption Time: {encryption_time:.6f} seconds")

#     # RSA decryption
#     start_time = time.time()
#     decrypted_message = private_key_rsa.decrypt(
#         encrypted_message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     decryption_time = time.time() - start_time
#     print(f"RSA Decryption Time: {decryption_time:.6f} seconds")

#     assert message == decrypted_message, "RSA Decryption failed"
#     return keygen_time, encryption_time, decryption_time

# # Measure the time taken for ElGamal (ECC) key generation, encryption, and decryption
# def elgamal_performance(message):
#     print("\n--- ElGamal (ECC using secp256r1 curve) ---")

#     # ECC key generation (ECDH can simulate ElGamal-like key exchange)
#     start_time = time.time()
#     private_key_elgamal = ec.generate_private_key(ec.SECP256R1(), default_backend())
#     public_key_elgamal = private_key_elgamal.public_key()
#     keygen_time = time.time() - start_time
#     print(f"ECC Key Generation Time: {keygen_time:.6f} seconds")

#     # ECC encryption using a shared secret (simulated ElGamal encryption)
#     shared_secret = private_key_elgamal.exchange(ec.ECDH(), public_key_elgamal)
#     salt = os.urandom(16)

#     # Derive key from shared secret
#     kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
#     encryption_key = kdf.derive(shared_secret)

#     # Encryption (simulating ElGamal encryption)
#     start_time = time.time()
#     encrypted_message = b"".join([bytes([m ^ encryption_key[i % len(encryption_key)]]) for i, m in enumerate(message)])
#     encryption_time = time.time() - start_time
#     print(f"ECC Encryption Time: {encryption_time:.6f} seconds")

#     # Decryption (simulating ElGamal decryption)
#     start_time = time.time()
#     decrypted_message = b"".join([bytes([c ^ encryption_key[i % len(encryption_key)]]) for i, c in enumerate(encrypted_message)])
#     decryption_time = time.time() - start_time
#     print(f"ECC Decryption Time: {decryption_time:.6f} seconds")

#     assert message == decrypted_message, "ECC Decryption failed"
#     return keygen_time, encryption_time, decryption_time

# # Test for different message sizes
# message_sizes_kb = [1, 10]  # Test with 1 KB and 10 KB messages

# for size in message_sizes_kb:
#     print(f"\nTesting with message size: {size} KB")
#     message = generate_message(size)

#     # RSA performance
#     rsa_keygen_time, rsa_enc_time, rsa_dec_time = rsa_performance(message)

#     # ECC (ElGamal) performance
#     ecc_keygen_time, ecc_enc_time, ecc_dec_time = elgamal_performance(message)

#     # Comparison output
#     print(f"\nComparison for {size} KB message:")
#     print(f"RSA Keygen: {rsa_keygen_time:.6f}s, Encryption: {rsa_enc_time:.6f}s, Decryption: {rsa_dec_time:.6f}s")
#     print(f"ECC Keygen: {ecc_keygen_time:.6f}s, Encryption: {ecc_enc_time:.6f}s, Decryption: {ecc_dec_time:.6f}s")
