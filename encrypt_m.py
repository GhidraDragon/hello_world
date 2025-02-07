import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def load_public_key(public_key_file):
    """Load the public key from a file."""
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(public_key, message):
    """Encrypt a message using the public key."""
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def main():
    if len(sys.argv) != 3:
        print("Usage: python encrypt_message.py <public_key_file> <message>")
        sys.exit(1)

    public_key_file = sys.argv[1]
    message = sys.argv[2]

    # Load the public key
    public_key = load_public_key(public_key_file)

    # Encrypt the message
    encrypted_message = encrypt_message(public_key, message)

    # Output the encrypted message in base64 for readability
    import base64
    print("Encrypted message (base64):")
    print(base64.b64encode(encrypted_message).decode('utf-8'))

if __name__ == "__main__":
    main()