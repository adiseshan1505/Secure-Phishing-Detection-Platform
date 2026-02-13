import random
import string
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app import Base


class TwoFactorAuth(Base):
    __tablename__ = "2fa_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    otp_code = Column(String(6), nullable=False)
    is_verified = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    attempts = Column(Integer, default=0)
    max_attempts = 5

    @staticmethod
    def generate_otp() -> str:
        return "".join(random.choices(string.digits, k=6))

    @staticmethod
    def create_otp(db, user_id: int, expiry_minutes: int = 5) -> str:
        db.query(TwoFactorAuth).filter(
            TwoFactorAuth.user_id == user_id,
            TwoFactorAuth.is_verified == False
        ).delete()
        db.commit()

        otp = TwoFactorAuth.generate_otp()
        token = TwoFactorAuth(
            user_id=user_id,
            otp_code=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes)
        )
        db.add(token)
        db.commit()
        return otp

    @staticmethod
    def verify_otp(db, user_id: int, otp_code: str) -> bool:
        token = db.query(TwoFactorAuth).filter(
            TwoFactorAuth.user_id == user_id,
            TwoFactorAuth.otp_code == otp_code,
            TwoFactorAuth.is_verified == False
        ).first()

        if not token:
            return False

        if datetime.utcnow() > token.expires_at:
            db.delete(token)
            db.commit()
            return False

        if token.attempts >= token.max_attempts:
            db.delete(token)
            db.commit()
            return False

        token.is_verified = True
        token.attempts += 1
        db.commit()
        return True

    @staticmethod
    def invalidate_all(db, user_id: int):
        db.query(TwoFactorAuth).filter(
            TwoFactorAuth.user_id == user_id,
            TwoFactorAuth.is_verified == False
        ).delete()
        db.commit()
