from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import get_db, limiter
from app.models.user import User
from app.models.detection import DetectionResult
from app.utils.security import get_current_user_id
import logging

logger = logging.getLogger(__name__)
dashboard_router = APIRouter()


@dashboard_router.get("/stats")
async def get_stats(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        total_analyses = db.query(DetectionResult).filter_by(user_id=user_id).count()
        phishing_detected = db.query(DetectionResult).filter_by(user_id=user_id, is_phishing=True).count()
        legitimate = total_analyses - phishing_detected

        avg_risk = db.query(func.avg(DetectionResult.risk_score))\
            .filter(DetectionResult.user_id == user_id).scalar() or 0

        high_risk = db.query(DetectionResult).filter(
            DetectionResult.user_id == user_id,
            DetectionResult.risk_score > 75
        ).count()

        medium_risk = db.query(DetectionResult).filter(
            DetectionResult.user_id == user_id,
            DetectionResult.risk_score.between(50, 75)
        ).count()

        low_risk = db.query(DetectionResult).filter(
            DetectionResult.user_id == user_id,
            DetectionResult.risk_score < 50
        ).count()

        return {
            "total_analyses": total_analyses,
            "phishing_detected": phishing_detected,
            "legitimate_urls": legitimate,
            "average_risk_score": round(avg_risk, 2),
            "risk_distribution": {
                "high": high_risk,
                "medium": medium_risk,
                "low": low_risk
            },
            "detection_rate": round((phishing_detected / total_analyses * 100) if total_analyses > 0 else 0, 2)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Stats retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@dashboard_router.get("/recent")
@limiter.limit("20/minute")
async def get_recent(
    request: Request,
    limit: int = 10,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if limit > 50:
            limit = 50

        results = db.query(DetectionResult).filter_by(user_id=user_id)\
            .order_by(DetectionResult.timestamp.desc())\
            .limit(limit)\
            .all()

        return {
            "count": len(results),
            "results": [r.to_dict() for r in results]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Recent results error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve recent results")


@dashboard_router.get("/report")
async def get_report(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        rule_based = db.query(DetectionResult).filter_by(user_id=user_id, detection_method="rule_based").count()
        ml_based = db.query(DetectionResult).filter_by(user_id=user_id, detection_method="ml_based").count()
        hybrid = db.query(DetectionResult).filter_by(user_id=user_id, detection_method="hybrid").count()

        avg_confidence = db.query(func.avg(DetectionResult.confidence))\
            .filter(DetectionResult.user_id == user_id).scalar() or 0

        return {
            "user": user.to_dict(),
            "detection_methods": {
                "rule_based": rule_based,
                "ml_based": ml_based,
                "hybrid": hybrid
            },
            "average_confidence": round(avg_confidence, 2),
            "member_since": user.created_at.isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate report")
