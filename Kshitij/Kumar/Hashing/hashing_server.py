import socket


def hash_function(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF
    return hash_value


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12346))
    server_socket.listen(1)
    print("Server is listening on port 12346...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connected by {client_address}")
        data = client_socket.recv(1024).decode()
        if not data:
            break

        print(f"Received data: {data}")

        # Compute the hash of the received data
        received_hash = hash_function(data)
        print(f"Computed hash: {received_hash}")

        # Send the hash back to the client
        client_socket.sendall(str(received_hash).encode())
        client_socket.close()

    server_socket.close()


if __name__ == "__main__":
    main()
