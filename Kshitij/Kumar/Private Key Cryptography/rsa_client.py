import socket


def rsa_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))

        while True:
            action = input("Enter 'encrypt' or 'decrypt' (or 'exit' to quit): ")
            if action.lower() == 'exit':
                break
            message = input("Enter the message: ")
            data = f"{action},{message}"
            s.sendall(data.encode())
            response = s.recv(1024).decode()
            print(f"Response: {response}")


if __name__ == "__main__":
    rsa_client()
