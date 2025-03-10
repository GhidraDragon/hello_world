import sys
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

def generate_key_pair(name, email, passphrase):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = PGPUID.new(name, email=email)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key

def main():
    if len(sys.argv) != 6:
        print("Usage: python generate_pgp_keys.py <name> <email> <passphrase> <private_key_file> <public_key_file>")
        sys.exit(1)

    name = sys.argv[1]
    email = sys.argv[2]
    passphrase = sys.argv[3]
    private_key_file = sys.argv[4]
    public_key_file = sys.argv[5]

    key = generate_key_pair(name, email, passphrase)

    with open(private_key_file, 'w') as pkf:
        pkf.write(str(key))

    with open(public_key_file, 'w') as pubf:
        pubf.write(str(key.pubkey))

if __name__ == "__main__":
    main()