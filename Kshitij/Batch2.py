from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
import hashlib

# Generate RSA Keys for the Doctor
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Doctor's Functionality
def encrypt_data(data):
    return public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_data(encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def sign_record(data):
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def hash_record(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Nurse and Admin Functionality
def verify_signature(data, signature):
    try:
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Example Usage
data = "Sensitive patient data"
encrypted_data = encrypt_data(data)
decrypted_data = decrypt_data(encrypted_data)
signature = sign_record(data)
hashed_record = hash_record(data)

print("Encrypted Data:", encrypted_data)
print("Decrypted Data:", decrypted_data)
print("Signature Valid:", verify_signature(data, signature))
print("Hash of Record:", hashed_record)