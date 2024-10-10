from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

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
    # Convert signature from integer to bytes
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
    # Step 1: Generate RSA Keys for Nurse and Doctor
    nurse_private_key, nurse_public_key = generate_rsa_keys()
    doctor_private_key, doctor_public_key = generate_rsa_keys()

    records = {}  # Dictionary to store multiple health records

    while True:
        display_menu()
        choice = input("Enter your choice (1-7): ")

        if choice == '1':  # Encrypt Message (Nurse to Doctor)
            patient_id = input("Enter Patient ID: ")
            message = input("Enter the message to encrypt: ").encode()
            encrypted_message = rsa_encrypt(doctor_public_key, message)
            records[patient_id] = {"encrypted_message": encrypted_message, "signature": None}  # Store encrypted message
            print(f"Encrypted Message (hex): {encrypted_message.hex()}")

        elif choice == '2':  # Decrypt Message (Doctor)
            patient_id = input("Enter Patient ID to decrypt: ")
            if patient_id in records and records[patient_id]["encrypted_message"]:
                decrypted_message = rsa_decrypt(doctor_private_key, records[patient_id]["encrypted_message"])
                print(f"Decrypted Message: {decrypted_message.decode()}")
            else:
                print("No record found or message not encrypted.")

        elif choice == '3':  # Sign Message (Nurse)
            patient_id = input("Enter Patient ID to sign: ")
            if patient_id in records and records[patient_id]["encrypted_message"]:
                message = input("Enter the message to sign: ").encode()
                signature = rsa_sign(nurse_private_key, message)
                records[patient_id]["signature"] = signature  # Store signature
                print(f"Digital Signature (hex): {signature.hex()}")
            else:
                print("No record found to sign.")

        elif choice == '4':  # Verify Signature (Doctor)
            patient_id = input("Enter Patient ID to verify: ")
            if patient_id in records and records[patient_id]["signature"]:
                message = input("Enter the original message: ").encode()
                signature = bytes.fromhex(input("Enter the signature (hex): "))
                if rsa_verify(nurse_public_key, message, signature):
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
                    print(f"Encrypted Message (hex): {data['encrypted_message'].hex() if data['encrypted_message'] else 'N/A'}")
                    print(f"Digital Signature (hex): {data['signature'].hex() if data['signature'] else 'N/A'}")
                print("=======================")

        elif choice == '7':  # Exit the program
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please choose a valid option.")

# Entry point of the program
if __name__ == "__main__":
    menu()