# client.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def send_data(sock, data):
    sock.sendall(len(data).to_bytes(4, byteorder='big'))
    sock.sendall(data)

def main():
    # Generate key pair
    private_key, public_key = generate_key_pair()
    print("RSA key pair generated.")

    # Get user input
    message = input("Enter your message: ")

    # Sign the message
    signature = sign_message(message, private_key)

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    # Send the public key, message, and signature
    send_data(client_socket, public_key)
    send_data(client_socket, message.encode())
    send_data(client_socket, signature)

    # Receive the verification result
    result_length = int.from_bytes(client_socket.recv(4), byteorder='big')
    result = client_socket.recv(result_length).decode()
    print(f"Server response: {result}")

    client_socket.close()

if __name__ == "__main__":
    main()