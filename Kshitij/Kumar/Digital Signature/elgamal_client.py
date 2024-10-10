import socket
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Random import random

# ElGamal Key Generation
def generate_elgamal_keys(bits=256):
    p = number.getPrime(bits)
    g = random.randint(2, p-2)
    private_key = random.randint(1, p-2)
    public_key = pow(g, private_key, p)
    return p, g, private_key, public_key

# ElGamal Sign
def elgamal_sign(message, p, g, private_key):
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')
    while True:
        k = random.randint(1, p-2)
        if number.GCD(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = number.inverse(k, p-1)
    s = (k_inv * (h - private_key * r)) % (p-1)
    return r, s

# Client code
def client_program():
    p, g, private_key, public_key = generate_elgamal_keys()

    # Collect message from user input
    message = input("Enter the message to be signed: ")

    # Signing the message
    r, s = elgamal_sign(message, p, g, private_key)

    # Prepare data to be sent to server
    data = {
        'message': message,
        'r': r,
        's': s,
        'p': p,
        'g': g,
        'public_key': public_key
    }

    # Connect to the server
    client_socket = socket.socket()
    host = '127.0.0.1'
    port = 65432

    try:
        client_socket.connect((host, port))

        # Send the signed message and public key
        client_socket.sendall(str(data).encode())

        # Receive verification response from server
        verification_result = client_socket.recv(1024).decode()
        print(f"Server Response: {verification_result}")

    finally:
        client_socket.close()

if __name__ == "__main__":
    client_program()
