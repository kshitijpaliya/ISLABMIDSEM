import socket


def elgamal_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65433))

        while True:
            action = input("Enter 'encrypt' or 'decrypt' (or 'exit' to quit): ")
            if action.lower() == 'exit':
                break
            if action == 'encrypt':
                message = int(input("Enter the message (as an integer): "))
                data = f"{action},{message}"
            elif action == 'decrypt':
                c1 = int(input("Enter c1: "))
                c2 = int(input("Enter c2: "))
                data = f"{action},{c1},{c2}"
            else:
                print("Invalid action!")
                continue

            s.sendall(data.encode())
            response = s.recv(1024).decode()
            print(f"Response: {response}")


if __name__ == "__main__":
    elgamal_client()
