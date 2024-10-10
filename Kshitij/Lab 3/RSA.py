from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA keypair
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

# Encrypt using RSA
def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

# Decrypt using RSA
def rsa_decrypt(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()

# Main execution
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    message = input("Enter a message to encrypt (RSA): ")

    encrypted = rsa_encrypt(public_key, message)
    print("Encrypted:", encrypted)

    decrypted = rsa_decrypt(private_key, encrypted)
    print("Decrypted:", decrypted)