from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64


class EncryptionManager:
    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt_data(data: str, password: str) -> str:
        key, salt = EncryptionManager.derive_key(password)
        cipher = Fernet(key)
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(salt + encrypted).decode()

    @staticmethod
    def decrypt_data(encrypted_data: str, password: str) -> str:
        try:
            combined = base64.b64decode(encrypted_data.encode())
            salt = combined[:16]
            encrypted = combined[16:]
            key, _ = EncryptionManager.derive_key(password, salt)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def generate_secure_key() -> str:
        return Fernet.generate_key().decode()
