from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import get_db, limiter
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.security import get_current_user_id, role_required
import logging

logger = logging.getLogger(__name__)
admin_router = APIRouter()


@admin_router.get("/users")
@limiter.limit("10/minute")
async def get_users(
    request: Request,
    page: int = 1,
    per_page: int = 10,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        if per_page > 50:
            per_page = 50

        total = db.query(User).count()
        users = db.query(User)\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()

        return {
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "current_page": page,
            "users": [u.to_dict() for u in users]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Users retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")


@admin_router.get("/users/{target_user_id}")
async def get_user(
    target_user_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        user = db.query(User).filter(User.id == target_user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "user": user.to_dict(),
            "analyses_count": len(user.detection_results)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User details error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user details")


@admin_router.put("/users/{target_user_id}/toggle")
async def toggle_user_status(
    target_user_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        user = db.query(User).filter(User.id == target_user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user_id == target_user_id:
            raise HTTPException(status_code=400, detail="Cannot modify own account")

        user.is_active = not user.is_active
        db.commit()

        action = "activated" if user.is_active else "deactivated"
        logger.info(f"Admin {user_id} {action} user {user.username}")

        return {
            "message": f"User {action} successfully",
            "user": user.to_dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"User status toggle error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to toggle user status")


@admin_router.get("/audit-logs")
@limiter.limit("10/minute")
async def get_audit_logs(
    request: Request,
    page: int = 1,
    per_page: int = 20,
    action: str = None,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        if per_page > 100:
            per_page = 100

        query = db.query(AuditLog)
        if action:
            query = query.filter(AuditLog.action == action)

        total = query.count()
        logs = query.order_by(AuditLog.timestamp.desc())\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()

        return {
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "current_page": page,
            "logs": [l.to_dict() for l in logs]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audit logs retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit logs")


@admin_router.get("/statistics")
@limiter.limit("10/minute")
async def get_statistics(
    request: Request,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        role_required(db, user_id, "admin")

        total_users = db.query(User).count()
        active_users = db.query(User).filter_by(is_active=True).count()
        admin_users = db.query(User).filter_by(role="admin").count()
        analyst_users = db.query(User).filter_by(role="analyst").count()
        regular_users = db.query(User).filter_by(role="user").count()

        from app.models.detection import DetectionResult
        total_analyses = db.query(DetectionResult).count()
        phishing_detected = db.query(DetectionResult).filter_by(is_phishing=True).count()

        return {
            "users": {
                "total": total_users,
                "active": active_users,
                "by_role": {
                    "admin": admin_users,
                    "analyst": analyst_users,
                    "user": regular_users
                }
            },
            "analyses": {
                "total": total_analyses,
                "phishing_detected": phishing_detected,
                "detection_rate": round((phishing_detected / total_analyses * 100) if total_analyses > 0 else 0, 2)
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Statistics error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")
