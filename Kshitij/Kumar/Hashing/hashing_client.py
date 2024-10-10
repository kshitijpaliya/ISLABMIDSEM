import socket


def hash_function(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF
    return hash_value


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12346))

    # Take user input for data
    data = input("Enter the data to send to the server: ")
    client_socket.sendall(data.encode())

    # Receive the hash from the server
    received_hash = client_socket.recv(1024).decode()
    print(f"Received hash from server: {received_hash}")

    # Compute the hash of the sent data locally
    local_hash = hash_function(data)
    print(f"Local computed hash: {local_hash}")

    # Verify the integrity of the data
    if str(local_hash) == received_hash:
        print("Data integrity verified.")
    else:
        print("Data integrity check failed. Data may have been corrupted or tampered with.")

    client_socket.close()


if __name__ == "__main__":
    main()
