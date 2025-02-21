import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

parser = argparse.ArgumentParser()
parser.add_argument("--file", required=True)
parser.add_argument("--password", required=True)
args = parser.parse_args()

content = open(args.file, "rb").read()
salt, iv, enc_data = content[:16], content[16:32], content[32:]
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(args.password.encode())
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
decryptor = cipher.decryptor()
dec_data = decryptor.update(enc_data) + decryptor.finalize()
open(args.file + ".dec", "wb").write(dec_data)
