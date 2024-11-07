# client.py

import socket
import base64
from RSAKeys import generate_rsa_key_pair, serialize_public_key, load_private_key, load_public_key
from EncrDecry import decrypt_message
from Sign import verify_signature
from hashing import hash_message
# client.py

def add_base64_padding(data):
    """Add padding to base64 encoded data if necessary."""
    return data + b'=' * (-len(data) % 4)

def start_client(host='localhost', port=5000):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")
    return client_socket

def run_client():
    client_socket = start_client()

    # Generate client's RSA key pair
    client_private_key, client_public_key = generate_rsa_key_pair()

    # Send client's public key to the server
    client_public_key_pem = serialize_public_key(client_public_key)
    client_socket.sendall(client_public_key_pem)

    # Send message to server
    message = b"Hello, secure server!"
    client_socket.sendall(message)

    # Receive encrypted message and signature from the server
    encrypted_message_and_signature = client_socket.recv(4096)
    encrypted_message_b64, signature_b64 = encrypted_message_and_signature.split(b'||')

    # Add padding if necessary and decode from base64
    encrypted_message = base64.b64decode(add_base64_padding(encrypted_message_b64))
    signature = base64.b64decode(add_base64_padding(signature_b64))

    # Decrypt the message with the client's private key
    decrypted_message = decrypt_message(client_private_key, encrypted_message)
    print("Decrypted message:", decrypted_message.decode())

    # Calculate the hash of the decrypted message
    decrypted_message_hash = hash_message(decrypted_message)

    # Load server public key for signature verification (replace with the actual server public key)
    server_public_key = load_public_key(serialize_public_key(client_public_key))  # Placeholder; replace with actual server's public key

    # Verify the signature using the server's public key
    is_valid_signature = verify_signature(server_public_key, decrypted_message_hash, signature)
    if is_valid_signature:
        print("Signature is valid. Message is authentic and intact.")
    else:
        print("Signature verification failed.")

    client_socket.close()

if __name__ == '__main__':
    run_client()
