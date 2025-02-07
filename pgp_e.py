import sys
from pgpy import PGPKey, PGPMessage

def load_public_key(public_key_file):
    """Load the PGP public key from a file."""
    with open(public_key_file, "r") as key_file:
        key_data = key_file.read()
    public_key, _ = PGPKey.from_blob(key_data)
    return public_key

def encrypt_message(public_key, message):
    """Encrypt a message using the PGP public key."""
    pgp_message = PGPMessage.new(message, cleartext=True)
    encrypted_message = public_key.encrypt(pgp_message)
    return str(encrypted_message)

def main():
    if len(sys.argv) != 3:
        print("Usage: python encrypt_pgp_message.py <public_key_file> <message>")
        sys.exit(1)

    public_key_file = sys.argv[1]
    message = sys.argv[2]

    # Load the public key
    public_key = load_public_key(public_key_file)

    # Encrypt the message
    encrypted_message = encrypt_message(public_key, message)

    # Output the encrypted message
    print("Encrypted message:")
    print(encrypted_message)

if __name__ == "__main__":
    main()