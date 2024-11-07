import socket
import json

class KeyManagementClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port

    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(json.dumps(request).encode())
            response = json.loads(s.recv(1024).decode())
        return response

    def menu(self):
        print("\n--- Key Management Menu ---")
        print("1. Generate Key")
        print("2. Renew Key")
        print("3. Revoke Key")
        print("4. Encrypt Message")
        print("5. Decrypt Message")
        print("6. Sign Message")
        print("7. Verify Signature")
        print("8. Exit")
        return input("Select an option: ")

    def run(self):
        username = input("Enter your username: ")
        while True:
            choice = self.menu()
            if choice == '1':
                print(self.send_request({"action": "generate_key", "username": username}))
            elif choice == '2':
                print(self.send_request({"action": "renew_key", "username": username}))
            elif choice == '3':
                print(self.send_request({"action": "revoke_key", "username": username}))
            elif choice == '4':
                recipient = input("Enter the recipient's username for encryption: ")
                message = input("Enter message to encrypt: ")
                print(self.send_request({"action": "encrypt", "username": username, "recipient": recipient, "message": message}))
            elif choice == '5':
                ciphertext = input("Enter ciphertext to decrypt: ")
                print(self.send_request({"action": "decrypt", "username": username, "ciphertext": ciphertext}))
            elif choice == '6':
                message = input("Enter message to sign: ")
                print(self.send_request({"action": "sign", "username": username, "message": message}))
            elif choice == '7':
                sender = input("Enter the sender's username for verification: ")
                message = input("Enter message: ")
                signature = input("Enter signature: ")
                print(self.send_request({"action": "verify", "sender": sender, "message": message, "signature": signature}))
            elif choice == '8':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client = KeyManagementClient()
    client.run()
