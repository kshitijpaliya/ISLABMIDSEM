import hashlib

# String to be hashed
data1 = "Hello, world!"

# Create an MD5 hash object
md5_hash = hashlib.md5()

# Update the hash object with the bytes of the data
md5_hash.update(data1.encode())

# Get the hexadecimal representation of the hash
md5_hex = md5_hash.hexdigest()

print(f"MD5 Hash: {md5_hex}")


import hashlib

# String to be hashed
data2 = "Hello, world!"

# Create a SHA-256 hash object
sha256_hash = hashlib.sha256()

# Update the hash object with the bytes of the data
sha256_hash.update(data2.encode())

# Get the hexadecimal representation of the hash
sha256_hex = sha256_hash.hexdigest()

print(f"SHA-256 Hash: {sha256_hex}")

import hashlib

# String to be hashed
data3 = "Hello, world!"

# Create a SHA-1 hash object
sha1_hash = hashlib.sha1()

# Update the hash object with the bytes of the data
sha1_hash.update(data3.encode())

# Get the hexadecimal representation of the hash
sha1_hex = sha1_hash.hexdigest()

print(f"SHA-1 Hash: {sha1_hex}")
