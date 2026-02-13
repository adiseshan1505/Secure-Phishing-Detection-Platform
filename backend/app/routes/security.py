from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from app import get_db
from app.models.user import User
from app.utils.encoding import EncodingManager, HashingManager
from app.utils.encryption import EncryptionManager
from app.utils.digital_signature import DigitalSignature
from app.utils.access_control import AccessControlManager
from app.utils.security import get_current_user_id, role_required
import logging

logger = logging.getLogger(__name__)
security_router = APIRouter()


class TextRequest(BaseModel):
    text: str


class HashRequest(BaseModel):
    text: str
    salt: str = ""


class HMACRequest(BaseModel):
    text: str
    secret: str


class EncryptRequest(BaseModel):
    text: str
    password: str


class DecryptRequest(BaseModel):
    encrypted: str
    password: str


class SignRequest(BaseModel):
    text: str
    secret: str


class VerifySignatureRequest(BaseModel):
    text: str
    signature: str
    secret: str


@security_router.post("/encoding/base64")
async def encode_base64(data: TextRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text:
            raise HTTPException(status_code=400, detail="Text is required")

        encoded = EncodingManager.base64_encode(data.text)
        return {"original": data.text, "encoded": encoded, "type": "Base64"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Base64 encoding error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encoding failed")


@security_router.post("/encoding/hex")
async def encode_hex(data: TextRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text:
            raise HTTPException(status_code=400, detail="Text is required")

        encoded = EncodingManager.hex_encode(data.text)
        return {"original": data.text, "encoded": encoded, "type": "Hexadecimal"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Hex encoding error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encoding failed")


@security_router.post("/encoding/url")
async def encode_url(data: TextRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text:
            raise HTTPException(status_code=400, detail="Text is required")

        encoded = EncodingManager.url_encode(data.text)
        return {"original": data.text, "encoded": encoded, "type": "URL Encoding"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"URL encoding error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encoding failed")


@security_router.post("/hash/sha256")
async def hash_sha256(data: HashRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text:
            raise HTTPException(status_code=400, detail="Text is required")

        hash_value = HashingManager.sha256_hash(data.text, data.salt)
        return {"original": data.text, "salt": data.salt, "hash": hash_value, "algorithm": "SHA256"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SHA256 hashing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Hashing failed")


@security_router.post("/hash/sha512")
async def hash_sha512(data: HashRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text:
            raise HTTPException(status_code=400, detail="Text is required")

        hash_value = HashingManager.sha512_hash(data.text, data.salt)
        return {"original": data.text, "salt": data.salt, "hash": hash_value, "algorithm": "SHA512"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SHA512 hashing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Hashing failed")


@security_router.post("/hash/hmac")
async def hash_hmac(data: HMACRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text or not data.secret:
            raise HTTPException(status_code=400, detail="Text and secret are required")

        hash_value = HashingManager.hmac_hash(data.text, data.secret)
        return {"original": data.text, "secret": "***hidden***", "hash": hash_value, "algorithm": "HMAC-SHA256"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HMAC hashing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Hashing failed")


@security_router.post("/encrypt")
async def encrypt_data(data: EncryptRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text or not data.password:
            raise HTTPException(status_code=400, detail="Text and password are required")

        encrypted = EncryptionManager.encrypt_data(data.text, data.password)
        return {"original": data.text, "encrypted": encrypted, "algorithm": "Fernet (AES-128)"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed")


@security_router.post("/decrypt")
async def decrypt_data(data: DecryptRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.encrypted or not data.password:
            raise HTTPException(status_code=400, detail="Encrypted text and password are required")

        decrypted = EncryptionManager.decrypt_data(data.encrypted, data.password)
        return {"encrypted": data.encrypted, "decrypted": decrypted, "algorithm": "Fernet (AES-128)"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise HTTPException(status_code=500, detail="Decryption failed")


@security_router.post("/sign")
async def sign_data(data: SignRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text or not data.secret:
            raise HTTPException(status_code=400, detail="Text and secret are required")

        signature = DigitalSignature.generate_signature(data.text, data.secret)
        return {"data": data.text, "signature": signature, "algorithm": "HMAC-SHA256"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signature generation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Signature generation failed")


@security_router.post("/verify-signature")
async def verify_signature(data: VerifySignatureRequest, user_id: int = Depends(get_current_user_id)):
    try:
        if not data.text or not data.signature or not data.secret:
            raise HTTPException(status_code=400, detail="Text, signature, and secret are required")

        is_valid = DigitalSignature.verify_signature(data.text, data.signature, data.secret)
        return {"data": data.text, "signature": data.signature, "is_valid": is_valid, "algorithm": "HMAC-SHA256"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Signature verification failed")


@security_router.get("/acl/matrix")
async def get_acl_matrix(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        matrix = AccessControlManager.get_acl_matrix()
        return {"acl_matrix": {k: v for k, v in matrix.items()}, "description": "Role-based access control matrix"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ACL retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve ACL")
