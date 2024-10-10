from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Step 1: Generate RSA keys (public and private)
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Exporting keys (if needed for storage or transfer)
private_key_pem = private_key.export_key().decode('utf-8')
public_key_pem = public_key.export_key().decode('utf-8')

print("Private Key:")
print(private_key_pem)
print("Public Key:")
print(public_key_pem)

# Step 2: Signing the message
message = "Hello, this is a digitally signed message."
message_hash = SHA256.new(message.encode())
signature = pkcs1_15.new(private_key).sign(message_hash)

print(f"\nDigital Signature: {signature.hex()}")

# Step 3: Verifying the signature
try:
    pkcs1_15.new(public_key).verify(message_hash, signature)
    print("\nThe signature is valid.")
except (ValueError, TypeError):
    print("\nThe signature is not valid.")
