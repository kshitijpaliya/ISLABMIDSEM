import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# AES Key Generation
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key


# AES Encryption
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


# AES Decryption
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_data


# RSA Key Generation (2048-bit)
def generate_rsa_keys():
    start_time = time.time()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    end_time = time.time()
    key_generation_time = end_time - start_time

    return private_key, public_key, key_generation_time


# RSA Encryption of AES key
def rsa_encrypt_aes_key(aes_key, public_key):
    ciphertext = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# RSA Decryption of AES key
def rsa_decrypt_aes_key(encrypted_aes_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# ECC Key Generation (secp256r1)
def generate_ecc_keys():
    start_time = time.time()

    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )

    public_key = private_key.public_key()

    end_time = time.time()
    key_generation_time = end_time - start_time

    return private_key, public_key, key_generation_time


# ECC Encryption of AES Key using ECDH
def ecc_encrypt_aes_key(aes_key, private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive the AES key from the shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file transfer",
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


# ECC Decryption of AES Key using ECDH
def ecc_decrypt_aes_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive the AES key from the shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file transfer",
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


# Measure encryption and decryption time for RSA and ECC
def measure_performance(file_data, rsa_private_key, rsa_public_key, ecc_private_key, ecc_public_key):
    aes_key = generate_aes_key()

    # RSA Encryption
    start_time = time.time()
    rsa_encrypted_key = rsa_encrypt_aes_key(aes_key, rsa_public_key)
    rsa_encrypted_file = aes_encrypt(file_data, aes_key)
    rsa_encryption_time = time.time() - start_time

    # RSA Decryption
    start_time = time.time()
    rsa_decrypted_key = rsa_decrypt_aes_key(rsa_encrypted_key, rsa_private_key)
    rsa_decrypted_file = aes_decrypt(rsa_encrypted_file, rsa_decrypted_key)
    rsa_decryption_time = time.time() - start_time

    # ECC Encryption
    ecc_shared_key = generate_aes_key()  # New AES key for ECC

    start_time = time.time()
    ecc_shared_key_derived = ecc_encrypt_aes_key(ecc_shared_key, ecc_private_key, ecc_public_key)
    ecc_encrypted_file = aes_encrypt(file_data, ecc_shared_key_derived)
    ecc_encryption_time = time.time() - start_time

    # ECC Decryption
    start_time = time.time()
    ecc_decrypted_shared_key = ecc_decrypt_aes_key(ecc_private_key, ecc_public_key)
    ecc_decrypted_file = aes_decrypt(ecc_encrypted_file, ecc_decrypted_shared_key)
    ecc_decryption_time = time.time() - start_time

    return rsa_encryption_time, rsa_decryption_time, ecc_encryption_time, ecc_decryption_time


def main():
    # File data to encrypt (example with 1MB file)
    file_data = os.urandom(1024 * 1024)  # 1MB file

    # Generate RSA keys
    rsa_private_key, rsa_public_key, rsa_key_gen_time = generate_rsa_keys()
    print(f"RSA Key Generation Time: {rsa_key_gen_time:.6f} seconds")

    # Generate ECC keys
    ecc_private_key, ecc_public_key, ecc_key_gen_time = generate_ecc_keys()
    print(f"ECC Key Generation Time: {ecc_key_gen_time:.6f} seconds")

    # Measure performance for both RSA and ECC
    rsa_enc_time, rsa_dec_time, ecc_enc_time, ecc_dec_time = measure_performance(
        file_data, rsa_private_key, rsa_public_key, ecc_private_key, ecc_public_key
    )

    print("\nPerformance Metrics (1MB File):")
    print(f"RSA Encryption Time: {rsa_enc_time:.6f} seconds")
    print(f"RSA Decryption Time: {rsa_dec_time:.6f} seconds")
    print(f"ECC Encryption Time: {ecc_enc_time:.6f} seconds")
    print(f"ECC Decryption Time: {ecc_dec_time:.6f} seconds")


if __name__ == "__main__":
    main()
