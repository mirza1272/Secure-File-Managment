"""
RSA Model
Provides RSA key generation and key encryption/decryption
Used for wrapping AES keys
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class RSAModel:
    def generate_keys(self):
        """Generate RSA key pair (2048-bit)"""
        private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def encrypt_key(self, aes_key, public_key):
        """Encrypt AES key using RSA public key (OAEP padding)"""
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_key(self, encrypted_key, private_key):
        """Decrypt AES key using RSA private key"""
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def save_private_key(self, private_key, file_path, password=None):
        """Save private key to PEM file"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        )
        with open(file_path, 'wb') as f:
            f.write(pem)

    def save_public_key(self, public_key, file_path):
        """Save public key to PEM file"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(file_path, 'wb') as f:
            f.write(pem)

    def load_private_key(self, file_path, password=None):
        """Load private key from PEM file"""
        with open(file_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None
            )
        return private_key

    def load_public_key(self, file_path):
        """Load public key from PEM file"""
        with open(file_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key
