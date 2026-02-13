from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app import get_db, limiter
from app.models.user import User
from app.models.otp import OTP
from app.utils.security import create_access_token, get_current_user_id, log_audit
from app.utils.validation import validate_email, validate_username, validate_password, get_client_ip
from app.utils.email_service import EmailService
from app.utils.aes_crypto import AESCryptoManager, RSAKeyManager, SessionKeyStore
import base64
import logging

logger = logging.getLogger(__name__)
auth_router = APIRouter()


class RegisterRequest(BaseModel):
    username: str
    email: str
    phone_number: str = ""
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class OTPRequest(BaseModel):
    email: str


class OTPVerifyRequest(BaseModel):
    email: str
    otp: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class SecurePayload(BaseModel):
    session_id: str
    encrypted_payload: dict


@auth_router.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, data: RegisterRequest, db: Session = Depends(get_db)):
    try:
        if not validate_username(data.username):
            raise HTTPException(status_code=400, detail="Invalid username format (3-50 chars, alphanumeric)")

        if not validate_email(data.email):
            raise HTTPException(status_code=400, detail="Invalid email format")

        valid, msg = validate_password(data.password)
        if not valid:
            raise HTTPException(status_code=400, detail=msg)

        if db.query(User).filter(User.username == data.username).first():
            raise HTTPException(status_code=409, detail="Username already exists")

        if db.query(User).filter(User.email == data.email).first():
            raise HTTPException(status_code=409, detail="Email already registered")

        user = User(
            username=data.username,
            email=data.email,
            phone_number=data.phone_number
        )
        user.set_password(data.password)

        db.add(user)
        db.commit()
        db.refresh(user)

        log_audit(db, user.id, "register", "success", get_client_ip(request), f"User {data.username} registered")
        logger.info(f"User registered: {data.username}")

        return {
            "message": "Registration successful",
            "user": user.to_dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@auth_router.post("/request-otp")
@limiter.limit("10/minute")
async def request_otp(request: Request, data: OTPRequest, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Email not registered")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is deactivated")

        otp_code, _ = OTP.create(db, data.email)
        email_sent = EmailService.send_otp(data.email, otp_code, user.username)

        if not email_sent:
            raise HTTPException(status_code=500, detail="Failed to send OTP email")

        return {"message": "OTP sent to your email", "email": data.email}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OTP request error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process OTP request")


@auth_router.post("/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(request: Request, data: OTPVerifyRequest, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        verified, message = OTP.verify(db, data.email, data.otp)
        if not verified:
            log_audit(db, user.id, "login_failed", "failed", get_client_ip(request), message)
            raise HTTPException(status_code=401, detail=message)

        token = create_access_token(user.id)

        log_audit(db, user.id, "login", "success", get_client_ip(request), "OTP login successful")
        logger.info(f"User logged in: {user.username}")

        return {
            "message": "Login successful",
            "token": token,
            "user": user.to_dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OTP verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")


@auth_router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, data: LoginRequest, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == data.username).first()

        if not user or not user.check_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account deactivated")

        token = create_access_token(user.id)
        log_audit(db, user.id, "login", "success", get_client_ip(request), "Password login")
        return {"message": "Login successful", "token": token, "user": user.to_dict()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


@auth_router.post("/logout")
async def logout(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    log_audit(db, user_id, "logout", "success")
    return {"message": "Logged out successfully"}


@auth_router.get("/profile")
async def get_profile(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user.to_dict()}


@auth_router.post("/change-password")
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    data: ChangePasswordRequest,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.check_password(data.old_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    valid, msg = validate_password(data.new_password)
    if not valid:
        raise HTTPException(status_code=400, detail=msg)

    user.set_password(data.new_password)
    db.commit()

    return {"message": "Password changed successfully"}


@auth_router.post("/crypto/handshake")
@limiter.limit("20/minute")
async def crypto_handshake(request: Request):
    try:
        session_id, aes_key = SessionKeyStore.create_session()
        aes_key_b64 = base64.b64encode(aes_key).decode("utf-8")

        return {
            "session_id": session_id,
            "aes_key": aes_key_b64,
            "algorithm": "AES-256-GCM",
            "key_exchange": "direct",
            "expires_in": SessionKeyStore.SESSION_TIMEOUT
        }
    except Exception as e:
        logger.error(f"Handshake error: {str(e)}")
        raise HTTPException(status_code=500, detail="Handshake failed")


@auth_router.get("/crypto/public-key")
async def get_public_key():
    try:
        pub_key_pem = RSAKeyManager.get_public_key_pem()
        return {"public_key": pub_key_pem, "algorithm": "RSA-2048-OAEP"}
    except Exception as e:
        logger.error(f"Public key error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get public key")


@auth_router.post("/secure-register")
@limiter.limit("5/minute")
async def secure_register(request: Request, data: SecurePayload, db: Session = Depends(get_db)):
    try:
        aes_key = SessionKeyStore.get_key(data.session_id)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        payload = AESCryptoManager.decrypt_auth_payload(data.encrypted_payload, aes_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    try:
        username = payload.get("username", "")
        email = payload.get("email", "")
        phone_number = payload.get("phone_number", "")
        password = payload.get("password", "")

        if not all([username, email, password]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        if not validate_username(username):
            raise HTTPException(status_code=400, detail="Invalid username format")

        if not validate_email(email):
            raise HTTPException(status_code=400, detail="Invalid email format")

        valid, msg = validate_password(password)
        if not valid:
            raise HTTPException(status_code=400, detail=msg)

        if db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=409, detail="Username already exists")

        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=409, detail="Email already registered")

        user = User(username=username, email=email, phone_number=phone_number)
        user.set_password(password)

        db.add(user)
        db.commit()
        db.refresh(user)

        SessionKeyStore.destroy_session(data.session_id)
        log_audit(db, user.id, "secure_register", "success", get_client_ip(request), "AES-256-GCM encrypted registration")

        return {
            "message": "Registration successful (AES-256-GCM encrypted)",
            "user": user.to_dict(),
            "encryption": {"method": "AES-256-GCM", "integrity": "HMAC-SHA256"}
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Secure registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@auth_router.post("/secure-request-otp")
@limiter.limit("10/minute")
async def secure_request_otp(request: Request, data: SecurePayload, db: Session = Depends(get_db)):
    try:
        aes_key = SessionKeyStore.get_key(data.session_id)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        payload = AESCryptoManager.decrypt_auth_payload(data.encrypted_payload, aes_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    try:
        email = payload.get("email", "")
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Email not registered")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is deactivated")

        otp_code, _ = OTP.create(db, email)
        email_sent = EmailService.send_otp(email, otp_code, user.username)

        if not email_sent:
            raise HTTPException(status_code=500, detail="Failed to send OTP email")

        return {
            "message": "OTP sent (encrypted channel)",
            "email": email,
            "encryption": {"method": "AES-256-GCM", "integrity": "HMAC-SHA256"}
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Secure OTP request error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process OTP request")


@auth_router.post("/secure-verify-otp")
@limiter.limit("10/minute")
async def secure_verify_otp(request: Request, data: SecurePayload, db: Session = Depends(get_db)):
    try:
        aes_key = SessionKeyStore.get_key(data.session_id)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        payload = AESCryptoManager.decrypt_auth_payload(data.encrypted_payload, aes_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    try:
        email = payload.get("email", "")
        otp = payload.get("otp", "")

        if not email or not otp:
            raise HTTPException(status_code=400, detail="Email and OTP are required")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        verified, message = OTP.verify(db, email, otp)
        if not verified:
            log_audit(db, user.id, "secure_login_failed", "failed", get_client_ip(request), message)
            raise HTTPException(status_code=401, detail=message)

        token = create_access_token(user.id)
        SessionKeyStore.destroy_session(data.session_id)
        log_audit(db, user.id, "secure_login", "success", get_client_ip(request), "AES-256-GCM encrypted OTP login")

        return {
            "message": "Login successful (AES-256-GCM encrypted)",
            "token": token,
            "user": user.to_dict(),
            "encryption": {"method": "AES-256-GCM", "integrity": "HMAC-SHA256"}
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Secure OTP verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")
