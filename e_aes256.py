import argparse, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

parser = argparse.ArgumentParser()
parser.add_argument("--file", required=True)
parser.add_argument("--password", required=True)
args = parser.parse_args()

data = open(args.file, "rb").read()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(args.password.encode())
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(data) + encryptor.finalize()
open(args.file + ".enc", "wb").write(salt + iv + encrypted_data)
