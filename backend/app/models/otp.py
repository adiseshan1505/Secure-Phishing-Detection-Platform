from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime, timedelta
import secrets
import hashlib
from app import Base


class OTP(Base):
    __tablename__ = "otps"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(120), nullable=False, index=True)
    otp_hash = Column(String(255), nullable=False)
    otp_plain = Column(String(10), nullable=False)
    expiry = Column(DateTime, nullable=False)
    attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    @staticmethod
    def generate_otp():
        return "".join([str(secrets.randbelow(10)) for _ in range(6)])

    @staticmethod
    def hash_otp(otp):
        return hashlib.sha256(otp.encode()).hexdigest()

    @staticmethod
    def create(db, email, validity_minutes=5):
        otp_plain = OTP.generate_otp()
        otp_hash = OTP.hash_otp(otp_plain)

        db.query(OTP).filter(OTP.email == email).delete()

        otp = OTP(
            email=email,
            otp_hash=otp_hash,
            otp_plain=otp_plain,
            expiry=datetime.utcnow() + timedelta(minutes=validity_minutes)
        )
        db.add(otp)
        db.commit()

        return otp_plain, otp

    @staticmethod
    def verify(db, email, otp_input):
        otp = db.query(OTP).filter(OTP.email == email).first()

        if not otp:
            return False, "No OTP found for this email"

        if datetime.utcnow() > otp.expiry:
            db.query(OTP).filter(OTP.email == email).delete()
            db.commit()
            return False, "OTP expired"

        if otp.attempts >= 3:
            db.query(OTP).filter(OTP.email == email).delete()
            db.commit()
            return False, "Too many attempts. Request new OTP"

        input_hash = OTP.hash_otp(otp_input)
        if input_hash != otp.otp_hash:
            otp.attempts += 1
            db.commit()
            return False, f"Invalid OTP ({3 - otp.attempts} attempts left)"

        db.query(OTP).filter(OTP.email == email).delete()
        db.commit()
        return True, "OTP verified"
