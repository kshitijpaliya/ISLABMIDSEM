import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define Subsystems (Finance, HR, Supply Chain)
SUBSYSTEMS = ["Finance System (A)", "HR System (B)", "Supply Chain Management (C)"]

# Key Management System
class KeyManagementSystem:
    def __init__(self):
        self.subsystem_keys = {}

    # RSA Key Generation
    def generate_rsa_key_pair(self, subsystem_name):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.subsystem_keys[subsystem_name] = {
            "private_key": private_key,
            "public_key": public_key
        }
        return private_key, public_key

    # Diffie-Hellman Key Generation for shared secret
    def generate_dh_parameters(self):
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        return parameters

    # Generate and exchange keys using Diffie-Hellman
    def diffie_hellman_key_exchange(self, parameters, peer_public_key):
        private_key = parameters.generate_private_key()
        shared_key = private_key.exchange(peer_public_key)
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure communication',
            backend=default_backend()
        ).derive(shared_key)
        return private_key, symmetric_key

    # Revoke Keys (dummy for demonstration)
    def revoke_keys(self, subsystem_name):
        if subsystem_name in self.subsystem_keys:
            del self.subsystem_keys[subsystem_name]
            print(f"Keys for {subsystem_name} have been revoked.")
        else:
            print(f"No keys found for {subsystem_name}")

# RSA Encryption/Decryption
def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Secure Communication System
class SecureCommunicationSystem:
    def __init__(self, kms):
        self.kms = kms
        self.dh_params = self.kms.generate_dh_parameters()

    # Establish secure communication using RSA and DH key exchange
    def establish_secure_channel(self, subsystem_name, peer_public_key):
        print(f"Establishing secure channel for {subsystem_name}...")
        private_key, symmetric_key = self.kms.diffie_hellman_key_exchange(self.dh_params, peer_public_key)
        print(f"Secure channel established with {subsystem_name}.")
        return symmetric_key

    # Encrypt document using RSA
    def secure_document_transfer(self, subsystem_name, document, recipient_public_key):
        print(f"Encrypting document for {subsystem_name}...")
        encrypted_document = rsa_encrypt(document, recipient_public_key)
        print(f"Document encrypted for {subsystem_name}.")
        return encrypted_document

    # Decrypt document using RSA
    def receive_secure_document(self, encrypted_document, subsystem_private_key):
        print(f"Decrypting received document...")
        decrypted_document = rsa_decrypt(encrypted_document, subsystem_private_key)
        print(f"Document decrypted.")
        return decrypted_document

# Main Program for SecureCorp
def main():
    # Initialize Key Management System (KMS)
    kms = KeyManagementSystem()

    # Generate RSA Key Pairs for all subsystems
    for subsystem in SUBSYSTEMS:
        print(f"Generating RSA key pair for {subsystem}...")
        kms.generate_rsa_key_pair(subsystem)

    # Secure Communication System
    secure_comm_system = SecureCommunicationSystem(kms)

    # Simulate Document Transfer from Finance System to HR System
    document = b"Confidential Financial Report"
    print("\n--- Finance System (A) to HR System (B) Document Transfer ---")

    # Finance System (A) public key and HR System (B) private key
    finance_public_key = kms.subsystem_keys["Finance System (A)"]["public_key"]
    hr_private_key = kms.subsystem_keys["HR System (B)"]["private_key"]

    # Encrypt document with HR's public key (simulating RSA)
    encrypted_document = secure_comm_system.secure_document_transfer(
        "HR System (B)", document, kms.subsystem_keys["HR System (B)"]["public_key"])

    # Decrypt document with HR's private key
    decrypted_document = secure_comm_system.receive_secure_document(encrypted_document, hr_private_key)
    print(f"Decrypted Document: {decrypted_document}")

    # Simulate Key Exchange (Diffie-Hellman)
    print("\n--- Secure Key Exchange using Diffie-Hellman ---")
    dh_private_key_finance, shared_key_finance = secure_comm_system.establish_secure_channel(
        "Finance System (A)", kms.dh_params.generate_private_key().public_key())

    print(f"Shared symmetric key (Finance): {shared_key_finance.hex()}")

    # Revoke Keys for a subsystem (Example)
    kms.revoke_keys("HR System (B)")

if __name__ == "__main__":
    main()
    