# server.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def receive_data(sock):
    data_length = int.from_bytes(sock.recv(4), byteorder='big')
    return sock.recv(data_length)

def send_data(sock, data):
    sock.sendall(len(data).to_bytes(4, byteorder='big'))
    sock.sendall(data)

def main():
    # Set up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)

    print("Server is listening...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address}")

        try:
            # Receive the public key, message, and signature
            public_key = receive_data(client_socket)
            message = receive_data(client_socket).decode()
            signature = receive_data(client_socket)

            # Verify the signature
            is_valid = verify_signature(message, signature, public_key)

            # Send the result back to the client
            result = "Signature is valid" if is_valid else "Signature is invalid"
            send_data(client_socket, result.encode())

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    main()