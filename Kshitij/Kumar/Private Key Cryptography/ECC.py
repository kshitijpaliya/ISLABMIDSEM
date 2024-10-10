from ecdsa import SigningKey, VerifyingKey, SECP256k1


# Generate ECC keypair
def generate_ecc_keypair():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


# Sign a message using ECC
def ecc_sign(private_key, message):
    return private_key.sign(message.encode())


# Verify a message using ECC
def ecc_verify(public_key, signature, message):
    return public_key.verify(signature, message.encode())


# Main execution
if __name__ == "__main__":
    private_key, public_key = generate_ecc_keypair()
    message = input("Enter a message to sign (ECC): ")

    signature = ecc_sign(private_key, message)
    print("Signature (hex):", signature.hex())

    is_valid = ecc_verify(public_key, signature, message)
    print("Signature valid:", is_valid)
