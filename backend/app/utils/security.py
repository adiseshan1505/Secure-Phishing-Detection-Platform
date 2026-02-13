from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app import get_db, JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_MINUTES
from app.models.audit_log import AuditLog
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security_scheme = HTTPBearer()


def create_access_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode = {"sub": str(user_id), "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> int:
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def log_audit(db: Session, user_id, action, status, ip_address="", description=""):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource="auth",
        description=description,
        ip_address=ip_address,
        status=status,
    )
    db.add(log)
    db.commit()


def role_required(db: Session, user_id: int, *allowed_roles):
    from app.models.user import User

    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user
