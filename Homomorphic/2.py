import socket
import json
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from phe import paillier  # Library for Paillier encryption
from cryptography.hazmat.primitives import hashes

class KeyManagementServer:
    def __init__(self, host='localhost', port=12349):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.keys = {}  # Dictionary to store RSA keys for multiplicative homomorphism
        self.paillier_keys = {}  # Dictionary to store Paillier keys for additive homomorphism
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
                break

    def stop_server(self):
        print("Shutting down the server...")
        self.is_running = False
        self.server_socket.close()

    # def handle_client(self, client_socket):
        # data = client_socket.recv(1024).decode()
        # request = json.loads(data)
        # action = request.get("action")

        # if action == "generate_key":
        #     response = self.generate_key(request["username"])
        # elif action == "renew_key":
        #     response = self.renew_key(request["username"])
        # elif action == "revoke_key":
        #     response = self.revoke_key(request["username"])
        # elif action == "encrypt_multiplicative":
        #     response = self.encrypt_multiplicative(request["username"], request["message"])
        # elif action == "decrypt_multiplicative":
        #     response = self.decrypt_multiplicative(request["username"], request["ciphertext"])
        # elif action == "encrypt_additive":
        #     response = self.encrypt_additive(request["username"], request["message"])
        # elif action == "decrypt_additive":
        #     response = self.decrypt_additive(request["username"], request["ciphertext"])
        # elif action == "add_encrypted":
        #     response = self.add_encrypted(request["username"], request["ciphertext1"], request["ciphertext2"])
        # elif action == "multiply_encrypted":
        #     response = self.multiply_encrypted(request["username"], request["ciphertext"], request["factor"])
        # elif action == "sign":
        #     response = self.sign(request["username"], request["message"])
        # elif action == "verify":
        #     response = self.verify(request["sender"], request["message"], request["signature"])
        # else:
        #     response = {"status": "error", "message": "Invalid action"}

        # client_socket.send(json.dumps(response).encode())
        # client_socket.close()
    def handle_client(self, client_socket):
        try:
            # Receive data with a large buffer and handle delimiters for complete JSON messages
            data = b""
            while True:
                packet = client_socket.recv(4096)
                if not packet:
                    break
                data += packet
                # Check if data contains the delimiter indicating the end of a JSON message
                if b"\n" in data:
                    break

            # Convert received data to string and split by delimiter to ensure full JSON
            message = data.decode().split("\n")[0]  # Take the first complete JSON message
            request = json.loads(message)
            action = request.get("action")

            # Process the request as per the action specified
            if action == "generate_key":
                response = self.generate_key(request["username"])
            elif action == "renew_key":
                response = self.renew_key(request["username"])
            elif action == "revoke_key":
                response = self.revoke_key(request["username"])
            elif action == "encrypt_multiplicative":
                response = self.encrypt_multiplicative(request["username"], request["message"])
            elif action == "decrypt_multiplicative":
                response = self.decrypt_multiplicative(request["username"], request["ciphertext"])
            elif action == "encrypt_additive":
                response = self.encrypt_additive(request["username"], request["message"])
            elif action == "decrypt_additive":
                response = self.decrypt_additive(request["username"], request["ciphertext"])
            elif action == "add_encrypted":
                response = self.add_encrypted(request["username"], request["ciphertext1"], request["ciphertext2"])
            elif action == "multiply_encrypted":
                response = self.multiply_encrypted(request["username"], request["ciphertext"], request["factor"])
            elif action == "sign":
                response = self.sign(request["username"], request["message"])
            elif action == "verify":
                response = self.verify(request["sender"], request["message"], request["signature"])
            else:
                response = {"status": "error", "message": "Invalid action"}

            # Send the response with a delimiter
            client_socket.send((json.dumps(response) + "\n").encode())
        except json.JSONDecodeError:
            print("Received incomplete or malformed JSON data.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            client_socket.close()


    def generate_key(self, username):
        # Generate RSA key for multiplicative homomorphism
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys[username] = private_key

        # Generate Paillier key pair for additive homomorphism
        public_key, private_key_paillier = paillier.generate_paillier_keypair()
        self.paillier_keys[username] = (public_key, private_key_paillier)

        print(f"Generated RSA and Paillier keys for {username}")
        return {"status": "success", "message": "Keys generated"}

    def encrypt_multiplicative(self, username, message):
        if username not in self.keys:
            return {"status": "error", "message": "Key not found"}
        public_key = self.keys[username].public_key()
        ciphertext = public_key.encrypt(
            int(message).to_bytes((int(message).bit_length() + 7) // 8, byteorder='big'),
            asym_padding.PKCS1v15()
        )
        print(f"RSA encrypted message (multiplicative) for {username}: {ciphertext.hex()}")
        return {"status": "success", "ciphertext": ciphertext.hex()}

    def decrypt_multiplicative(self, username, ciphertext):
        if username not in self.keys:
            return {"status": "error", "message": "Key not found"}
        private_key = self.keys[username]
        decrypted = int.from_bytes(private_key.decrypt(bytes.fromhex(ciphertext), asym_padding.PKCS1v15()), byteorder='big')
        print(f"RSA decrypted message for {username}: {decrypted}")
        return {"status": "success", "plaintext": str(decrypted)}

    def encrypt_additive(self, username, message):
        if username not in self.paillier_keys:
            return {"status": "error", "message": "Key not found"}
        public_key, _ = self.paillier_keys[username]
        ciphertext = public_key.encrypt(int(message))
        print(f"Paillier encrypted message (additive) for {username}: {ciphertext.ciphertext()}")
        return {"status": "success", "ciphertext": ciphertext.ciphertext()}

    def decrypt_additive(self, username, ciphertext):
        if username not in self.paillier_keys:
            return {"status": "error", "message": "Key not found"}
        _, private_key = self.paillier_keys[username]
        decrypted = private_key.decrypt(paillier.EncryptedNumber(self.paillier_keys[username][0], int(ciphertext)))
        print(f"Paillier decrypted message for {username}: {decrypted}")
        return {"status": "success", "plaintext": str(decrypted)}

    def add_encrypted(self, username, ciphertext1, ciphertext2):
        if username not in self.paillier_keys:
            return {"status": "error", "message": "Key not found"}
        public_key, _ = self.paillier_keys[username]
        encrypted_number1 = paillier.EncryptedNumber(public_key, int(ciphertext1))
        encrypted_number2 = paillier.EncryptedNumber(public_key, int(ciphertext2))
        result = encrypted_number1 + encrypted_number2
        print(f"Addition of encrypted numbers for {username}: {result.ciphertext()}")
        return {"status": "success", "ciphertext": result.ciphertext()}

    def multiply_encrypted(self, username, ciphertext, factor):
        if username not in self.paillier_keys:
            return {"status": "error", "message": "Key not found"}
        public_key, _ = self.paillier_keys[username]
        encrypted_number = paillier.EncryptedNumber(public_key, int(ciphertext))
        result = encrypted_number * int(factor)
        print(f"Multiplication of encrypted number by {factor} for {username}: {result.ciphertext()}")
        return {"status": "success", "ciphertext": result.ciphertext()}

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
            return {"status": "error", "message": "Sender's key not found"}
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
            return {"status": "success", "message": "Signature verified"}
        except Exception as e:
            return {"status": "error", "message": "Verification failed"}

if __name__ == "__main__":
    server = KeyManagementServer()
    server_thread = threading.Thread(target=server.start_server)
    server_thread.start()

    input("Press Enter to stop the server...\n")
    server.stop_server()
    server_thread.join()
