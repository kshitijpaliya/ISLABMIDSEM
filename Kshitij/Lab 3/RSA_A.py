from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import base64

def RSA_key_gen():
    key = RSA.generate(2048)
    public_key = key.publickey()
    #key is private here
    return key, public_key

def RSA_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def RSA_decrypt(key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

def main():
    # -----------------------------------rsa-----------------------------------
    message = b'Asymmetric Encryption'
    key, public_key = RSA_key_gen()
    ciphertext = RSA_encrypt(public_key, message)
    
    
    decrypted_message = RSA_decrypt(key, ciphertext)
    
    ciphertext=base64.b64encode(ciphertext).decode('ascii')
    print(f"Original Message: {message}")
    print(f"Ciphertext (as ascii): {ciphertext}")
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == '__main__':
    main()