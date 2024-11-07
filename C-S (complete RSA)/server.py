import socket
import json
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

class KeyManagementServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.keys = {}  # Dictionary to store user keys
        self.is_running = True  # Flag for controlling the server loop

    def start_server(self):
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        while self.is_running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except OSError:
                # Server has been closed, exit the loop
                break

    def stop_server(self):
        print("Shutting down the server...")
        self.is_running = False
        self.server_socket.close()

    def handle_client(self, client_socket):
        data = client_socket.recv(1024).decode()
        request = json.loads(data)
        action = request.get("action")

        if action == "generate_key":
            response = self.generate_key(request["username"])
        elif action == "renew_key":
            response = self.renew_key(request["username"])
        elif action == "revoke_key":
            response = self.revoke_key(request["username"])
        elif action == "encrypt":
            response = self.encrypt(request["username"], request["recipient"], request["message"])
        elif action == "decrypt":
            response = self.decrypt(request["username"], request["ciphertext"])
        elif action == "sign":
            response = self.sign(request["username"], request["message"])
        elif action == "verify":
            response = self.verify(request["sender"], request["message"], request["signature"])
        else:
            response = {"status": "error", "message": "Invalid action"}

        client_socket.send(json.dumps(response).encode())
        client_socket.close()

    def generate_key(self, username):
        if username in self.keys:
            return {"status": "error", "message": "Key already exists"}
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.keys[username] = private_key
        print(f"Generated key for {username}")
        return {"status": "success", "message": "Key generated"}

    def renew_key(self, username):
        if username not in self.keys:
            return {"status": "error", "message": "Key does not exist"}
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.keys[username] = private_key
        print(f"Renewed key for {username}")
        return {"status": "success", "message": "Key renewed"}

    def revoke_key(self, username):
        if username in self.keys:
            del self.keys[username]
            print(f"Revoked key for {username}")
            return {"status": "success", "message": "Key revoked"}
        else:
            print(f"Key not found for {username} to revoke")
            return {"status": "error", "message": "Key not found"}

    def encrypt(self, username, recipient, message):
        if recipient not in self.keys:
            return {"status": "error", "message": "Recipient's key not found"}
        public_key = self.keys[recipient].public_key()
        ciphertext = public_key.encrypt(
            message.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Encrypted message for {recipient}: {ciphertext.hex()}")
        return {"status": "success", "ciphertext": ciphertext.hex()}

    def decrypt(self, username, ciphertext):
        if username not in self.keys:
            return {"status": "error", "message": "Key not found"}
        private_key = self.keys[username]
        plaintext = private_key.decrypt(
            bytes.fromhex(ciphertext),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted message for {username}: {plaintext.decode()}")
        return {"status": "success", "plaintext": plaintext.decode()}

    def sign(self, username, message):
        if username not in self.keys:
            return {"status": "error", "message": "Key not found"}
        private_key = self.keys[username]
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"Generated signature for {username}: {signature.hex()}")
        return {"status": "success", "signature": signature.hex()}

    def verify(self, sender, message, signature):
        if sender not in self.keys:
            return {"status": "error", "message": "Sender's public key not found"}
        public_key = self.keys[sender].public_key()
        try:
            public_key.verify(
                bytes.fromhex(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"Signature verified for {sender} on message: {message}")
            return {"status": "success", "message": "Signature is valid"}
        except:
            print(f"Signature verification failed for {sender}")
            return {"status": "error", "message": "Invalid signature"}

if __name__ == "__main__":
    server = KeyManagementServer()
    server_thread = threading.Thread(target=server.start_server)
    server_thread.start()

    # Wait for user to press Enter to stop the server
    input("Press Enter to stop the server...\n")
    server.stop_server()
    server_thread.join()
