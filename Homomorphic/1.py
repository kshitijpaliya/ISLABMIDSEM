import socket
import json

class KeyManagementClient:
    def __init__(self, host='localhost', port=12349):
        self.host = host
        self.port = port

    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(json.dumps(request).encode())
            response = json.loads(s.recv(4096).decode())
        return response

    def menu(self):
        print("\n--- Key Management Menu ---")
        print("1. Generate Key")
        print("2. Encrypt Message (Multiplicative RSA)")
        print("3. Decrypt Message (Multiplicative RSA)")
        print("4. Encrypt Message (Additive Paillier)")
        print("5. Decrypt Message (Additive Paillier)")
        print("6. Add Encrypted Messages (Paillier)")
        print("7. Multiply Encrypted Message by Constant (Paillier)")
        print("8. Sign Message")
        print("9. Verify Signature")
        print("10. Exit")
        return input("Select an option: ")

    def run(self):
        username = input("Enter your username: ")
        while True:
            choice = self.menu()
            if choice == '1':
                print(self.send_request({"action": "generate_key", "username": username}))
            elif choice == '2':
                message = input("Enter an integer message to encrypt (Multiplicative RSA): ")
                print(self.send_request({"action": "encrypt_multiplicative", "username": username, "message": message}))
            elif choice == '3':
                ciphertext = input("Enter ciphertext to decrypt (Multiplicative RSA): ")
                print(self.send_request({"action": "decrypt_multiplicative", "username": username, "ciphertext": ciphertext}))
            elif choice == '4':
                message = input("Enter an integer message to encrypt (Additive Paillier): ")
                print(self.send_request({"action": "encrypt_additive", "username": username, "message": message}))
            elif choice == '5':
                ciphertext = input("Enter ciphertext to decrypt (Additive Paillier): ")
                print(self.send_request({"action": "decrypt_additive", "username": username, "ciphertext": ciphertext}))
            elif choice == '6':
                ciphertext1 = input("Enter first ciphertext to add (Paillier): ")
                ciphertext2 = input("Enter second ciphertext to add (Paillier): ")
                print(self.send_request({"action": "add_encrypted", "username": username, "ciphertext1": ciphertext1, "ciphertext2": ciphertext2}))
            elif choice == '7':
                ciphertext = input("Enter ciphertext to multiply by a constant (Paillier): ")
                factor = input("Enter the integer constant to multiply with: ")
                print(self.send_request({"action": "multiply_encrypted", "username": username, "ciphertext": ciphertext, "factor": factor}))
            elif choice == '8':
                message = input("Enter message to sign: ")
                print(self.send_request({"action": "sign", "username": username, "message": message}))
            elif choice == '9':
                sender = input("Enter sender's username: ")
                message = input("Enter message to verify: ")
                signature = input("Enter signature to verify: ")
                print(self.send_request({"action": "verify", "sender": sender, "message": message, "signature": signature}))
            elif choice == '10':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client = KeyManagementClient()
    client.run()
