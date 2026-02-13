import base64
import binascii
from urllib.parse import quote, unquote
import json
import hmac
import hashlib


class EncodingManager:
    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(encoded: str) -> str:
        try:
            return base64.b64decode(encoded.encode()).decode()
        except Exception as e:
            raise ValueError(f"Base64 decode failed: {str(e)}")

    @staticmethod
    def hex_encode(data: str) -> str:
        return binascii.hexlify(data.encode()).decode()

    @staticmethod
    def hex_decode(encoded: str) -> str:
        try:
            return binascii.unhexlify(encoded.encode()).decode()
        except Exception as e:
            raise ValueError(f"Hex decode failed: {str(e)}")

    @staticmethod
    def url_encode(data: str) -> str:
        return quote(data)

    @staticmethod
    def url_decode(encoded: str) -> str:
        return unquote(encoded)

    @staticmethod
    def json_encode(data: dict) -> str:
        return json.dumps(data)

    @staticmethod
    def json_decode(encoded: str) -> dict:
        try:
            return json.loads(encoded)
        except Exception as e:
            raise ValueError(f"JSON decode failed: {str(e)}")

    @staticmethod
    def ascii_encode(data: str) -> str:
        return " ".join(str(ord(c)) for c in data)

    @staticmethod
    def ascii_decode(encoded: str) -> str:
        try:
            return "".join(chr(int(code)) for code in encoded.split())
        except Exception as e:
            raise ValueError(f"ASCII decode failed: {str(e)}")

    @staticmethod
    def rot13(data: str) -> str:
        result = []
        for char in data:
            if "a" <= char <= "z":
                result.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                result.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(char)
        return "".join(result)


class HashingManager:
    @staticmethod
    def sha256_hash(data: str, salt: str = "") -> str:
        hash_input = f"{salt}{data}".encode()
        return hashlib.sha256(hash_input).hexdigest()

    @staticmethod
    def sha512_hash(data: str, salt: str = "") -> str:
        hash_input = f"{salt}{data}".encode()
        return hashlib.sha512(hash_input).hexdigest()

    @staticmethod
    def md5_hash(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def hmac_hash(data: str, secret: str) -> str:
        return hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_hash(data: str, hash_value: str, salt: str = "") -> bool:
        return HashingManager.sha256_hash(data, salt) == hash_value
