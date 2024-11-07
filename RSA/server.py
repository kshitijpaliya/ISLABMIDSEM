# server.py

import socket
import base64
from RSAKeys import generate_rsa_key_pair, load_public_key, load_private_key, serialize_public_key
from EncrDecry import encrypt_message
from Sign import sign_message
from hashing import hash_message


def start_server(host='localhost', port=5000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server is listening on {host}:{port}...")
    return server_socket

def run_server():
    server_socket = start_server()
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Generate or load the server's RSA key pair
    server_private_key, server_public_key = generate_rsa_key_pair()  # In practice, use a persistent key
    print("Server's public key for verification:", serialize_public_key(server_public_key))

    # Receive client's public key
    client_public_key_pem = conn.recv(2048)
    client_public_key = load_public_key(client_public_key_pem)

    # Receive message from client
    message = conn.recv(2048)
    if not message:
        print("No message received. Closing connection.")
        conn.close()
        return

    # Encrypt the message with the client's public key
    encrypted_message = encrypt_message(client_public_key, message)

    # Hash the message and sign the hash with the server's private key
    message_hash = hash_message(message)
    signature = sign_message(server_private_key, message_hash)

    # Base64 encode the encrypted message and signature
    encrypted_message_b64 = base64.b64encode(encrypted_message)
    signature_b64 = base64.b64encode(signature)

    # Send encoded encrypted message and signature to client
    conn.sendall(encrypted_message_b64 + b'||' + signature_b64)

    conn.close()

if __name__ == '__main__':
    run_server()
