from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional
from app import get_db, limiter
from app.models.user import User
from app.models.detection import DetectionResult
from app.ml_engine import HybridDetector
from app.utils.validation import validate_url, get_client_ip, get_user_agent
from app.utils.security import get_current_user_id
import numpy as np
import logging

logger = logging.getLogger(__name__)
detection_router = APIRouter()

detector = HybridDetector()


def sanitize_value(obj):
    if isinstance(obj, dict):
        return {k: sanitize_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_value(item) for item in obj]
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


class AnalyzeRequest(BaseModel):
    url: str
    email_content: str = ""


class BatchAnalyzeRequest(BaseModel):
    urls: List[str]


@detection_router.post("/analyze")
@limiter.limit("30/minute")
async def analyze_url(
    request: Request,
    data: AnalyzeRequest,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        url = data.url.strip()
        email_content = data.email_content.strip()

        if not url:
            raise HTTPException(status_code=400, detail="URL is required")

        if not validate_url(url):
            raise HTTPException(status_code=400, detail="Invalid URL format")

        result = sanitize_value(detector.detect(url, email_content))

        detection = DetectionResult(
            user_id=user_id,
            url=url,
            email_content=email_content if email_content else None,
            is_phishing=bool(result["is_phishing"]),
            risk_score=float(result["risk_score"]),
            confidence=float(result["confidence"]),
            rule_based_score=float(result["rule_based_score"]),
            ml_based_score=float(result["ml_based_score"]),
            detection_method=result["detection_method"],
            suspicious_features=result.get("suspicious_features"),
            url_analysis=result.get("rule_features"),
            ml_prediction_details=result.get("ml_details"),
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )

        db.add(detection)
        db.commit()
        db.refresh(detection)

        logger.info(f"URL analyzed by user {user.username}: {url} - Phishing: {result['is_phishing']}")

        return {
            "message": "Analysis complete",
            "result": {
                "id": detection.id,
                "url": url,
                "is_phishing": bool(result["is_phishing"]),
                "risk_score": round(float(result["risk_score"]), 2),
                "confidence": round(float(result["confidence"]), 2),
                "rule_based_score": round(float(result["rule_based_score"]), 2),
                "ml_based_score": round(float(result["ml_based_score"]), 2),
                "detection_method": result["detection_method"],
                "suspicious_features": result.get("suspicious_features"),
                "timestamp": detection.timestamp.isoformat()
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@detection_router.get("/history")
@limiter.limit("20/minute")
async def get_history(
    request: Request,
    page: int = 1,
    per_page: int = 10,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if per_page > 100:
            per_page = 100

        total = db.query(DetectionResult).filter_by(user_id=user_id).count()
        results = db.query(DetectionResult).filter_by(user_id=user_id)\
            .order_by(DetectionResult.timestamp.desc())\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()

        return {
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "current_page": page,
            "results": [r.to_dict() for r in results]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve history")


@detection_router.get("/result/{result_id}")
async def get_result(
    result_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        result = db.query(DetectionResult).filter_by(id=result_id, user_id=user_id).first()
        if not result:
            raise HTTPException(status_code=404, detail="Result not found")

        return result.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Result retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve result")


@detection_router.post("/batch")
@limiter.limit("10/minute")
async def batch_analyze(
    request: Request,
    data: BatchAnalyzeRequest,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if not data.urls or len(data.urls) == 0:
            raise HTTPException(status_code=400, detail="URLs list is required")

        if len(data.urls) > 50:
            raise HTTPException(status_code=400, detail="Maximum 50 URLs allowed per batch")

        results = []

        for url in data.urls:
            url = url.strip()

            if not url or not validate_url(url):
                results.append({"url": url, "error": "Invalid URL format"})
                continue

            detection_result = sanitize_value(detector.detect(url))

            detection = DetectionResult(
                user_id=user_id,
                url=url,
                is_phishing=bool(detection_result["is_phishing"]),
                risk_score=float(detection_result["risk_score"]),
                confidence=float(detection_result["confidence"]),
                rule_based_score=float(detection_result["rule_based_score"]),
                ml_based_score=float(detection_result["ml_based_score"]),
                detection_method=detection_result["detection_method"],
                suspicious_features=detection_result.get("suspicious_features"),
                url_analysis=detection_result.get("rule_features"),
                ml_prediction_details=detection_result.get("ml_details"),
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )

            db.add(detection)

            results.append({
                "url": url,
                "is_phishing": bool(detection_result["is_phishing"]),
                "risk_score": round(float(detection_result["risk_score"]), 2),
                "confidence": round(float(detection_result["confidence"]), 2)
            })

        db.commit()

        logger.info(f"Batch analysis by user {user.username}: {len(data.urls)} URLs")

        return {
            "message": "Batch analysis complete",
            "total": len(results),
            "results": results
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Batch analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail="Batch analysis failed")
