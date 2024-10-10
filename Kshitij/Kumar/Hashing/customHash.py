def hash_function(input_string):
    # Initialize the hash value
    hash_value = 5381

    # Iterate over each character in the input string
    for char in input_string:
        # Update the hash value using the specified operations
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF

    return hash_value


if __name__ == "__main__":
    # Take input from the user
    user_input = input("Enter a string to hash: ")
    # Compute the hash value
    result = hash_function(user_input)
    # Print the hash value
    print(f"Hash value for '{user_input}': {result}")
