"""
AES Encryption Model
Provides AES-256 encryption and decryption using CFB mode
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os


class AESModel:
    def __init__(self, key):
        """Initialize with a 32-byte key for AES-256"""
        self.key = key

    def encrypt(self, file_path):
        """Encrypt a file and return IV + encrypted data"""
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv))
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Return IV + encrypted data
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, encrypted_data):
        """Decrypt data (expects IV + encrypted data format)"""
        # Extract IV and actual encrypted data
        iv = encrypted_data[:16]
        actual_encrypted_data = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        return decryptor.update(actual_encrypted_data) + decryptor.finalize()
