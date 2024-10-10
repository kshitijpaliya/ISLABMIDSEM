from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import socket


def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()


def rsa_decrypt(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()


def start_server():
    private_key, public_key = generate_rsa_keypair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
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
                if command == 'encrypt':
                    encrypted = rsa_encrypt(public_key, message)
                    conn.sendall(encrypted.encode())
                elif command == 'decrypt':
                    decrypted = rsa_decrypt(private_key, message)
                    conn.sendall(decrypted.encode())


if __name__ == "__main__":
    start_server()
