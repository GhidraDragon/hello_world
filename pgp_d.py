import sys
from pgpy import PGPKey, PGPMessage

def load_private_key(private_key_file, passphrase):
    """Load the PGP private key from a file."""
    with open(private_key_file, "r") as key_file:
        key_data = key_file.read()
    private_key, _ = PGPKey.from_blob(key_data)
    
    # Unlock the private key with the passphrase
    if private_key.is_protected:
        private_key.unlock(passphrase)
    
    return private_key

def decrypt_message(private_key, encrypted_message):
    """Decrypt a message using the PGP private key."""
    pgp_message = PGPMessage.from_blob(encrypted_message)
    decrypted_message = private_key.decrypt(pgp_message).message
    return decrypted_message

def main():
    if len(sys.argv) != 4:
        print("Usage: python decrypt_pgp_message.py <private_key_file> <passphrase> <encrypted_message>")
        sys.exit(1)

    private_key_file = sys.argv[1]
    passphrase = sys.argv[2]
    encrypted_message = sys.argv[3]

    # Load the private key
    private_key = load_private_key(private_key_file, passphrase)

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_message)

    # Output the decrypted message
    print("Decrypted message:")
    print(decrypted_message)

if __name__ == "__main__":
    main()