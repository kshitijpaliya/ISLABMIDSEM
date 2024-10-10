from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import os
from datetime import datetime, timedelta

# --- DRM Key Management System using RSA ---
class DRMKeyManagement:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_key_pair = None
        self.access_control_list = {}
        self.logs = []

    def generate_master_key(self):
        self.master_key_pair = RSA.generate(self.key_size)
        self.log_action(f"Generated master public-private key pair with size {self.key_size} bits")

    def log_action(self, action):
        log_entry = f"{datetime.now()} - {action}"
        self.logs.append(log_entry)

    def get_logs(self):
        return '\n'.join(self.logs)

# --- Content Encryption Management ---
class ContentManagement:
    def __init__(self, drm):
        self.drm = drm

    def encrypt_content(self, content, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_content = cipher.encrypt(content.encode())
        return base64.b64encode(encrypted_content).decode()

# --- RSA Encryption and Decryption ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher.encrypt(message)

def rsa_decrypt(private_key, encrypted_message):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher.decrypt(encrypted_message)

def rsa_sign(private_key, message):
    private_key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pow(int.from_bytes(h.digest(), 'big'), private_key.d, private_key.n)
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, 'big')
    return signature_bytes

def rsa_verify(public_key, message, signature):
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    hash_value = int.from_bytes(h.digest(), 'big')
    return (pow(int.from_bytes(signature, 'big'), public_key.e, public_key.n) == hash_value)

# --- Hashing ---
def generate_hash(message):
    h = SHA256.new(message)
    return h.digest()

# --- Secure Storage for Private Keys ---
class SecureStorage:
    def __init__(self, drm):
        self.drm = drm
        self.storage_path = "secure_storage/"

    def store_private_key(self):
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)

        with open(self.storage_path + "master_private_key.pem", "wb") as file:
            file.write(self.drm.master_key_pair.export_key())
        self.drm.log_action("Master private key securely stored")

    def load_private_key(self):
        with open(self.storage_path + "master_private_key.pem", "rb") as file:
            self.drm.master_key_pair = RSA.import_key(file.read())
        self.drm.log_action("Master private key loaded from secure storage")

# --- Display Nurse Menu ---
def display_nurse_menu():
    print("\n===== Nurse Menu =====")
    print("1. Encrypt Message (Nurse to Doctor)")
    print("2. Sign Message (Nurse)")
    print("3. Generate Hash")
    print("4. Logout")
    print("======================")

# --- Display Doctor Menu ---
def display_doctor_menu():
    print("\n===== Doctor Menu =====")
    print("1. Decrypt Message (Doctor)")
    print("2. Verify Signature (Doctor)")
    print("3. View All Records")
    print("4. Logout")
    print("======================")

# --- Role-based Access Control ---
def role_based_menu(role, nurse_private_key, nurse_public_key, doctor_private_key, doctor_public_key, records):
    while True:
        if role == 'nurse':
            display_nurse_menu()
            choice = input("Enter your choice (1-4): ")

            if choice == '1':
                patient_id = input("Enter Patient ID: ")
                message = input("Enter the message to encrypt: ").encode()
                encrypted_message = rsa_encrypt(doctor_public_key, message)
                records[patient_id] = {"encrypted_message": encrypted_message, "signature": None}
                print(f"Encrypted Message (hex): {encrypted_message.hex()}")

            elif choice == '2':
                patient_id = input("Enter Patient ID to sign: ")
                if patient_id in records and records[patient_id]["encrypted_message"]:
                    message = input("Enter the message to sign: ").encode()
                    signature = rsa_sign(nurse_private_key, message)
                    records[patient_id]["signature"] = signature
                    print(f"Digital Signature (hex): {signature.hex()}")
                else:
                    print("No record found to sign.")

            elif choice == '3':
                message = input("Enter the message to generate hash: ").encode()
                hash_value = generate_hash(message)
                print(f"SHA-256 Hash (hex): {hash_value.hex()}")

            elif choice == '4':
                print("Logging out.")
                break

            else:
                print("Invalid choice! Please choose a valid option.")

        elif role == 'doctor':
            display_doctor_menu()
            choice = input("Enter your choice (1-4): ")

            if choice == '1':
                patient_id = input("Enter Patient ID to decrypt: ")
                if patient_id in records and records[patient_id]["encrypted_message"]:
                    decrypted_message = rsa_decrypt(doctor_private_key, records[patient_id]["encrypted_message"])
                    print(f"Decrypted Message: {decrypted_message.decode()}")
                else:
                    print("No record found or message not encrypted.")

            elif choice == '2':
                patient_id = input("Enter Patient ID to verify: ")
                if patient_id in records and records[patient_id]["signature"]:
                    message = input("Enter the original message: ").encode()
                    signature = bytes.fromhex(input("Enter the signature (hex): "))
                    if rsa_verify(nurse_public_key, message, signature):
                        print("Signature is valid.")
                    else:
                        print("Invalid signature.")
                else:
                    print("No record found or signature not available.")

            elif choice == '3':
                print("All Records:")
                for patient, data in records.items():
                    print(f"Patient ID: {patient}, Encrypted Message (hex): {data['encrypted_message'].hex()}, Signature (hex): {data['signature'].hex() if data['signature'] else 'None'}")

            elif choice == '4':
                print("Logging out.")
                break

            else:
                print("Invalid choice! Please choose a valid option.")

# --- Main Menu ---
def main():
    # Step 1: Initialize the DRM system
    drm_system = DRMKeyManagement(key_size=2048)
    secure_storage = SecureStorage(drm=drm_system)

    # Step 2: Admin generates the master key for DRM (RSA)
    drm_system.generate_master_key()
    print("\nAdmin generated DRM master key.")

    # Step 3: Securely store the master key
    secure_storage.store_private_key()

    # Step 4: Generate RSA keys for Nurse and Doctor
    nurse_private_key, nurse_public_key = generate_rsa_keys()
    doctor_private_key, doctor_public_key = generate_rsa_keys()

    # Records for encrypted messages and signatures
    records = {}

    # Step 5: Main Menu
    while True:
        print("\n===== Main Menu =====")
        print("1. Nurse Operations")
        print("2. Doctor Operations")
        print("3. Exit")
        print("======================")
        choice = input("Enter your role (1-3): ")

        if choice == '1':
            # Nurse Operations
            role_based_menu('nurse', nurse_private_key, nurse_public_key, doctor_private_key, doctor_public_key, records)

        elif choice == '2':
            # Doctor Operations
            role_based_menu('doctor', nurse_private_key, nurse_public_key, doctor_private_key, doctor_public_key, records)

        elif choice == '3':
            print("Exiting the system.")
            break

        else:
            print("Invalid choice! Please choose a valid option.")

if __name__ == '__main__':
    main()
