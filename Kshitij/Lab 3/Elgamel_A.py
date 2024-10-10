from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import base64

def ElGamal_key_gen(bits=2048):
    p = getPrime(bits)
    g = random.randint(2, p-1)
    x = random.randint(2, p-1)
    h = pow(g, x, p)
    return (p, g, h), x


def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    # Convert message to integer
    m = bytes_to_long(message)

    # Step 2: Encryption
    y = random.randint(1, p - 2)  # Random integer
    c1 = pow(g, y, p)  # c1 = g^y mod p
    c2 = (m * pow(h, y, p)) % p  # c2 = m * h^y mod p

    return (c1, c2)  # Return the ciphertext


def elgamal_decrypt(private_key, ciphertext, public_key):
    p, _, _ = public_key
    c1, c2 = ciphertext
    x = private_key  # Private key

    # Step 3: Decryption
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = inverse(s, p)  # Find the modular inverse of s
    m_prime = (c2 * s_inv) % p  # m' = c2 * s^(-1) mod p

    return long_to_bytes(m_prime)  # Convert back to bytes

def main():
     #-----------------------------------elgamal-----------------------------------
    message = b'Confidential Data'

    # Generate ElGamal public and private keys
    public_key, private_key = ElGamal_key_gen()

    # Encrypt the message with the public key
    ciphertext = elgamal_encrypt(public_key, message)
    print(f"Encrypted ciphertext: c1 = {ciphertext[0]}, c2 = {ciphertext[1]}")

    # Decrypt the ciphertext with the private key
    decrypted_message = elgamal_decrypt(private_key, ciphertext, public_key)
    print("Decrypted message:", decrypted_message.decode())

if __name__ == '__main__':
    main()