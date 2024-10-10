import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# Generate ECC key pair using secp256r1 curve
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# ElGamal Encryption using ECC (Elliptic Curve ElGamal)
def elgamal_encrypt(patient_data, recipient_public_key):
    # Step 1: Generate ephemeral private key for encryption
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Step 2: Compute the shared secret using ECDH
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Step 3: Derive a symmetric key from the shared secret using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
        backend=default_backend()
    ).derive(shared_secret)

    # Step 4: Encrypt the patient data using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(patient_data) + encryptor.finalize()

    return ephemeral_public_key, iv + ciphertext

# ElGamal Decryption using ECC
def elgamal_decrypt(ephemeral_public_key, encrypted_data, recipient_private_key):
    # Step 1: Compute the shared secret using ECDH
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Step 2: Derive the symmetric key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
        backend=default_backend()
    ).derive(shared_secret)

    # Step 3: Decrypt the data using AES
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    return decrypted_data

# Measure encryption and decryption performance
def measure_performance(patient_data):
    # Step 1: Generate ECC key pairs for the doctor (sender) and hospital (recipient)
    private_key_hospital, public_key_hospital = generate_ecc_key_pair()

    # Encryption Performance
    start_time = time.time()
    ephemeral_public_key, encrypted_data = elgamal_encrypt(patient_data, public_key_hospital)
    encryption_time = time.time() - start_time

    # Decryption Performance
    start_time = time.time()
    decrypted_data = elgamal_decrypt(ephemeral_public_key, encrypted_data, private_key_hospital)
    decryption_time = time.time() - start_time

    # Check if decryption is successful
    assert decrypted_data == patient_data, "Decryption failed: Data mismatch!"

    return encryption_time, decryption_time

def main():
    # Test with patient data of varying sizes (1MB, 10MB)
    patient_data_1mb = os.urandom(1024 * 1024)  # 1MB of random data
    patient_data_10mb = os.urandom(10 * 1024 * 1024)  # 10MB of random data

    # Measure performance for 1MB file
    print("Measuring performance for 1MB patient data:")
    encryption_time_1mb, decryption_time_1mb = measure_performance(patient_data_1mb)
    print(f"Encryption Time (1MB): {encryption_time_1mb:.6f} seconds")
    print(f"Decryption Time (1MB): {decryption_time_1mb:.6f} seconds")

    # Measure performance for 10MB file
    print("\nMeasuring performance for 10MB patient data:")
    encryption_time_10mb, decryption_time_10mb = measure_performance(patient_data_10mb)
    print(f"Encryption Time (10MB): {encryption_time_10mb:.6f} seconds")
    print(f"Decryption Time (10MB): {decryption_time_10mb:.6f} seconds")

if __name__ == "__main__":
    main()
