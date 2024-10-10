from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate fixed ECC private and public keys
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Message to be encrypted
message = b"Secure Transactions"

# Step 1: Encrypt the message using the public key
# Derive shared secret from the fixed private key and public key
shared_secret = private_key.exchange(ec.ECDH(), public_key)

# Derive key from the shared secret using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_secret)

# Encrypt the message using the derived key with AES
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag

# Step 2: Decrypt the ciphertext using the private key
# Derive the same shared secret from the fixed private key and public key
shared_secret2 = private_key.exchange(ec.ECDH(), public_key)

# Derive the same key from the shared secret using HKDF
derived_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_secret2)

# Decrypt the message using the derived key with AES
decryptor = Cipher(
    algorithms.AES(derived_key2),
    modes.GCM(iv, tag),
    backend=default_backend()
).decryptor()

decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

# Print results
print(f"Original Message: {message.decode('utf-8')}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")