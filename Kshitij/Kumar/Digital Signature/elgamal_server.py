import socket
from Crypto.Hash import SHA256

# ElGamal Verify
def elgamal_verify(message, r, s, p, g, public_key):
    hash_obj = SHA256.new(message.encode())
    h = int.from_bytes(hash_obj.digest(), byteorder='big')
    v1 = (pow(public_key, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# Server code
def server_program():
    server_socket = socket.socket()
    host = '127.0.0.1'
    port = 65432
    server_socket.bind((host, port))

    server_socket.listen(1)
    print(f"Server is listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connection from: {addr}")

    try:
        # Receive data from the client
        data = conn.recv(1024).decode()
        data = eval(data)  # Convert string data back to dictionary

        # Extract the data
        message = data['message']
        r = data['r']
        s = data['s']
        p = data['p']
        g = data['g']
        public_key = data['public_key']

        # Verify the signature
        is_valid = elgamal_verify(message, r, s, p, g, public_key)
        if is_valid:
            conn.sendall("Signature is valid.".encode())
        else:
            conn.sendall("Signature is invalid.".encode())

    finally:
        conn.close()

if __name__ == "__main__":
    server_program()
