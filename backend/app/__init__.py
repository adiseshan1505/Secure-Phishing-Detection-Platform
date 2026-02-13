from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./instance/phishing_db.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
JWT_SECRET_KEY = os.getenv("JWT_SECRET", "dev-jwt-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

limiter = Limiter(key_func=get_remote_address)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Phishing Detection Platform",
        version="2.0.0"
    )

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from app.routes.auth import auth_router
    from app.routes.detection import detection_router
    from app.routes.dashboard import dashboard_router
    from app.routes.admin import admin_router
    from app.routes.security import security_router

    app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(detection_router, prefix="/api/detection", tags=["Detection"])
    app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
    app.include_router(admin_router, prefix="/api/admin", tags=["Admin"])
    app.include_router(security_router, prefix="/api/security", tags=["Security"])

    Base.metadata.create_all(bind=engine)

    try:
        from app.utils.access_control import AccessControlManager
        db = SessionLocal()
        AccessControlManager.initialize_acl(db)
        db.close()
    except Exception as e:
        print(f"ACL initialization note: {e}")

    return app
