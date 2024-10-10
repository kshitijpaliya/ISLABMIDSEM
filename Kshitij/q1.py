import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util import number


# --- Diffie-Hellman Key Exchange ---
def generate_dh_parameters():
    p = number.getPrime(2048)  # Generate a large prime number
    g = random.randint(2, p - 1)  # Choose a generator
    return p, g


def generate_dh_keys(p, g):
    private_key = random.randint(2, p - 2)  # Private key
    public_key = pow(g, private_key, p)  # Public key: g^private_key mod p
    return private_key, public_key


def compute_shared_key(private_key, peer_public_key, p):
    return pow(peer_public_key, private_key, p)  # Shared key: peer_public_key^private_key mod p


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
    return pow(int.from_bytes(h.digest(), 'big'), private_key.d, private_key.n)


def rsa_verify(public_key, message, signature):
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    return (pow(signature, public_key.e, public_key.n) == int.from_bytes(h.digest(), 'big'))


# --- SecureCorp Communication System ---
class SecureCorp:
    def __init__(self, name):
        self.name = name
        self.p, self.g = generate_dh_parameters()
        self.private_key, self.public_key = generate_dh_keys(self.p, self.g)
        self.shared_key = None
        self.rsa_private_key, self.rsa_public_key = generate_rsa_keys()

    def compute_shared_key(self, peer_public_key):
        # Compute shared key using the integer public key
        self.shared_key = compute_shared_key(self.private_key, peer_public_key, self.p)

    def send_secure_message(self, peer_rsa_public_key, message):
        # Encrypt the message using the recipient's RSA public key
        encrypted_message = rsa_encrypt(peer_rsa_public_key, message)  # Encrypt with peer's RSA public key
        signature = rsa_sign(self.rsa_private_key, message)  # Sign the original message
        return encrypted_message, signature

    def receive_secure_message(self, encrypted_message, signature, sender_rsa_public_key):
        decrypted_message = rsa_decrypt(self.rsa_private_key, encrypted_message)  # Decrypt with own RSA private key
        if rsa_verify(sender_rsa_public_key, decrypted_message, signature):  # Verify signature using the sender's public key
            print(f"[{self.name}] Received secure message: {decrypted_message.decode()}")
        else:
            print(f"[{self.name}] Signature verification failed.")


# --- Main Communication Flow ---
def main():
    # Initialize subsystems
    finance_system = SecureCorp("Finance System")
    hr_system = SecureCorp("HR System")
    scm_system = SecureCorp("Supply Chain Management")

    # Simulate key exchange and communication
    # Finance sends a message to HR
    print("---- Secure Communication from Finance to HR ----")
    encrypted_message, signature = finance_system.send_secure_message(hr_system.rsa_public_key,  # Use the HR's RSA public key
                                                                      b"Financial Report: Q1 2024")
    hr_system.receive_secure_message(encrypted_message, signature, finance_system.rsa_public_key)  # Pass the sender's RSA public key

    # HR sends a message to Supply Chain Management
    print("\n---- Secure Communication from HR to SCM ----")
    encrypted_message, signature = hr_system.send_secure_message(scm_system.rsa_public_key,  # Use the SCM's RSA public key
                                                                 b"Employee Contracts: March 2024")
    scm_system.receive_secure_message(encrypted_message, signature, hr_system.rsa_public_key)  # Pass the sender's RSA public key

    # SCM sends a message back to Finance
    print("\n---- Secure Communication from SCM to Finance ----")
    encrypted_message, signature = scm_system.send_secure_message(finance_system.rsa_public_key,  # Use the Finance's RSA public key
                                                                  b"Procurement Order: PO#12345")
    finance_system.receive_secure_message(encrypted_message, signature, scm_system.rsa_public_key)  # Pass the sender's RSA public key


if __name__ == "__main__":
    main()
