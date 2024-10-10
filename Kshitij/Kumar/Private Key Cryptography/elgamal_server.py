import random
import socket


def generate_elgamal_keypair(p, g):
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def elgamal_encrypt(p, g, public_key, message):
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)
    c2 = (message * pow(public_key, y, p)) % p
    return c1, c2


def elgamal_decrypt(private_key, p, c1, c2):
    s = pow(c1, private_key, p)
    decrypted_message = (c2 * pow(s, p - 2, p)) % p
    return decrypted_message


def start_server():
    p = int(input("Enter a prime number (p): "))
    g = int(input("Enter a generator (g): "))
    private_key, public_key = generate_elgamal_keypair(p, g)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65433))
        s.listen()
        print("Server is listening...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                command, message = data.decode().split(',', 1)
                message = int(message)
                if command == 'encrypt':
                    c1, c2 = elgamal_encrypt(p, g, public_key, message)
                    conn.sendall(f"{c1},{c2}".encode())
                elif command == 'decrypt':
                    decrypted = elgamal_decrypt(private_key, p, message[0], message[1])
                    conn.sendall(str(decrypted).encode())


if __name__ == "__main__":
    start_server()
