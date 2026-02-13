from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint, func
from app import Base


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(20), nullable=False, index=True)
    permission = Column(String(20), nullable=False)
    resource = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=func.current_timestamp())

    __table_args__ = (UniqueConstraint("role", "permission", "resource"),)
