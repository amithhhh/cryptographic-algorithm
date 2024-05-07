from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import base64

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encryption(data, public_key):
    cipher_text = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(cipher_text).decode()

def decryption(data, private_key):
    decrypted = private_key.decrypt(
        base64.b64decode(data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

if __name__ == "__main__":
    choice = input("[+] Enter Your Choice (encryption/decryption): ")
    file_path = input("[+] Enter Your FilePath: ")

    if choice == 'encryption':
        private_key, public_key = generate_key_pair()
        with open(file_path, 'r') as f:
            data = f.read()
        ciphertext = encryption(data, public_key)
        print(f"[*] Cipher Text: {ciphertext}")
        with open('public_key.pem', 'wb') as pbf:
            pbf.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        with open('private_key.pem', 'wb') as prf:
            prf.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(file_path, 'w') as f:
            f.write(ciphertext)
    elif choice == 'decryption':
        with open('private_key.pem', 'rb') as prf:
            private_key = serialization.load_pem_private_key(
                prf.read(),
                password=None,
                backend=default_backend()
            )
        with open(file_path, 'r') as f:
            ciphertext = f.read()
        decrypted_data = decryption(ciphertext, private_key)
        print(f'[*] Original Data: {decrypted_data}')
        with open(file_path, 'w') as f:
            f.write(decrypted_data)
    else:
        exit()
