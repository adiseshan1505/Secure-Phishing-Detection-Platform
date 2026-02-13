import hmac
import hashlib
import base64
from datetime import datetime


class DigitalSignature:
    @staticmethod
    def generate_signature(data: str, secret: str) -> str:
        signature = hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(data: str, signature: str, secret: str) -> bool:
        try:
            expected_signature = DigitalSignature.generate_signature(data, secret)
            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False

    @staticmethod
    def sign_detection_result(result_data: dict, private_key: str) -> dict:
        timestamp = datetime.utcnow().isoformat()
        data_string = f"{result_data}_{timestamp}"
        signature = DigitalSignature.generate_signature(data_string, private_key)

        return {
            "data": result_data,
            "timestamp": timestamp,
            "signature": signature,
            "algorithm": "HMAC-SHA256"
        }

    @staticmethod
    def verify_signed_result(signed_result: dict, private_key: str) -> bool:
        data_string = f"{signed_result['data']}_{signed_result['timestamp']}"
        return DigitalSignature.verify_signature(
            data_string,
            signed_result["signature"],
            private_key
        )

    @staticmethod
    def generate_certificate(user_id: int, email: str, org: str = "Cyber Lab") -> dict:
        cert_data = {
            "user_id": user_id,
            "email": email,
            "organization": org,
            "issued_at": datetime.utcnow().isoformat(),
            "valid_for_days": 365
        }

        cert_string = str(cert_data)
        signature = DigitalSignature.generate_signature(cert_string, email)

        return {
            **cert_data,
            "certificate_id": base64.b64encode(
                f"{user_id}_{int(datetime.utcnow().timestamp())}".encode()
            ).decode(),
            "signature": signature
        }
