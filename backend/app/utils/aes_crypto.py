import os
import base64
import json
import hmac
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCryptoManager:
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 200000) -> tuple:
        if salt is None:
            salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> dict:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "algorithm": "AES-256-GCM"
        }

    @staticmethod
    def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
        aesgcm = AESGCM(key)
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_auth_payload(payload: dict, key: bytes) -> dict:
        payload["_timestamp"] = int(time.time())
        payload_json = json.dumps(payload, sort_keys=True)
        encrypted = AESCryptoManager.encrypt(payload_json, key)

        hmac_digest = hmac.new(
            key,
            encrypted["ciphertext"].encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        encrypted["hmac"] = hmac_digest
        return encrypted

    @staticmethod
    def decrypt_auth_payload(encrypted_data: dict, key: bytes, max_age_seconds: int = 300) -> dict:
        expected_hmac = hmac.new(
            key,
            encrypted_data["ciphertext"].encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(encrypted_data.get("hmac", ""), expected_hmac):
            raise ValueError("HMAC verification failed - payload tampered")

        payload_json = AESCryptoManager.decrypt(
            encrypted_data["ciphertext"],
            encrypted_data["nonce"],
            key
        )
        payload = json.loads(payload_json)

        timestamp = payload.pop("_timestamp", 0)
        if abs(time.time() - timestamp) > max_age_seconds:
            raise ValueError("Payload expired - possible replay attack")

        return payload


class RSAKeyManager:
    _private_key = None
    _public_key = None

    @classmethod
    def generate_keypair(cls):
        cls._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        cls._public_key = cls._private_key.public_key()

    @classmethod
    def get_public_key_pem(cls) -> str:
        if cls._public_key is None:
            cls.generate_keypair()

        pem = cls._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode("utf-8")

    @classmethod
    def decrypt_with_private_key(cls, encrypted_b64: str) -> bytes:
        if cls._private_key is None:
            raise ValueError("RSA keypair not initialized")

        encrypted = base64.b64decode(encrypted_b64)
        plaintext = cls._private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


class SessionKeyStore:
    _sessions = {}
    SESSION_TIMEOUT = 600

    @classmethod
    def create_session(cls) -> tuple:
        session_id = secrets.token_urlsafe(32)
        aes_key = AESCryptoManager.generate_key()

        cls._sessions[session_id] = {
            "key": aes_key,
            "created_at": time.time()
        }

        cls._cleanup()
        return session_id, aes_key

    @classmethod
    def get_key(cls, session_id: str) -> bytes:
        cls._cleanup()
        session = cls._sessions.get(session_id)
        if not session:
            raise ValueError("Session not found or expired")

        if time.time() - session["created_at"] > cls.SESSION_TIMEOUT:
            del cls._sessions[session_id]
            raise ValueError("Session expired")

        return session["key"]

    @classmethod
    def destroy_session(cls, session_id: str):
        cls._sessions.pop(session_id, None)

    @classmethod
    def _cleanup(cls):
        now = time.time()
        expired = [
            sid for sid, data in cls._sessions.items()
            if now - data["created_at"] > cls.SESSION_TIMEOUT
        ]
        for sid in expired:
            del cls._sessions[sid]
