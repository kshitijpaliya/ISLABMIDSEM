from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random
from Crypto.Hash import SHA256

# --- ElGamal Encryption and Decryption ---
def generate_elgamal_keys():
    key = ElGamal.generate(2048, random.get_random_bytes)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def elgamal_encrypt(public_key, message):
    k = random.StrongRandom().randint(1, public_key.p - 1)  # Random value for encryption
    cipher_text = public_key.encrypt(message, k)
    return cipher_text

def elgamal_decrypt(private_key, encrypted_message):
    return private_key.decrypt(encrypted_message)

def elgamal_sign(private_key, message):
    h = int.from_bytes(SHA256.new(message).digest(), 'big')
    k = random.StrongRandom().randint(1, private_key.p - 1)  # Random value for signing
    signature = private_key.sign(h, k)
    return signature

def elgamal_verify(public_key, message, signature):
    h = int.from_bytes(SHA256.new(message).digest(), 'big')
    return public_key.verify(h, signature)

# --- Hashing ---
def generate_hash(message):
    h = SHA256.new(message)
    return h.digest()

# Display the main menu
def display_menu():
    print("\n===== Access Control System =====")
    print("1. Encrypt Message (Nurse to Doctor)")
    print("2. Decrypt Message (Doctor)")
    print("3. Sign Message (Nurse)")
    print("4. Verify Signature (Doctor)")
    print("5. Generate Hash")
    print("6. View All Records")
    print("7. Exit")
    print("===================================")

# Menu-driven access control program
def menu():
    # Step 1: Generate ElGamal Keys for Nurse and Doctor
    nurse_private_key, nurse_public_key = generate_elgamal_keys()
    doctor_private_key, doctor_public_key = generate_elgamal_keys()

    records = {}  # Dictionary to store multiple health records

    while True:
        display_menu()
        choice = input("Enter your choice (1-7): ")

        if choice == '1':  # Encrypt Message (Nurse to Doctor)
            patient_id = input("Enter Patient ID: ")
            message = input("Enter the message to encrypt: ").encode()
            encrypted_message = elgamal_encrypt(doctor_public_key, message)
            records[patient_id] = {"encrypted_message": encrypted_message, "signature": None}  # Store encrypted message
            print(f"Encrypted Message: {encrypted_message}")

        elif choice == '2':  # Decrypt Message (Doctor)
            patient_id = input("Enter Patient ID to decrypt: ")
            if patient_id in records and records[patient_id]["encrypted_message"]:
                decrypted_message = elgamal_decrypt(doctor_private_key, records[patient_id]["encrypted_message"])
                print(f"Decrypted Message: {decrypted_message.decode()}")
            else:
                print("No record found or message not encrypted.")

        elif choice == '3':  # Sign Message (Nurse)
            patient_id = input("Enter Patient ID to sign: ")
            if patient_id in records and records[patient_id]["encrypted_message"]:
                message = input("Enter the message to sign: ").encode()
                signature = elgamal_sign(nurse_private_key, message)
                records[patient_id]["signature"] = signature  # Store signature
                print(f"Digital Signature: {signature}")
            else:
                print("No record found to sign.")

        elif choice == '4':  # Verify Signature (Doctor)
            patient_id = input("Enter Patient ID to verify: ")
            if patient_id in records and records[patient_id]["signature"]:
                message = input("Enter the original message: ").encode()
                signature = eval(input("Enter the signature: "))  # Use eval to interpret tuple format
                if elgamal_verify(nurse_public_key, message, signature):
                    print("Signature is valid.")
                else:
                    print("Invalid Signature.")
            else:
                print("No record found or signature not available.")

        elif choice == '5':  # Generate Hash
            message = input("Enter the message to generate hash: ").encode()
            hash_value = generate_hash(message)
            print(f"SHA-256 Hash (hex): {hash_value.hex()}")

        elif choice == '6':  # View All Records
            if not records:
                print("No records available.")
            else:
                print("\n=== Health Records ===")
                for patient_id, data in records.items():
                    print(f"Patient ID: {patient_id}")
                    print(f"Encrypted Message: {data['encrypted_message'] if data['encrypted_message'] else 'N/A'}")
                    print(f"Digital Signature: {data['signature'] if data['signature'] else 'N/A'}")
                print("=======================")

        elif choice == '7':  # Exit the program
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please choose a valid option.")

# Entry point of the program
if __name__ == "__main__":
    menu()
