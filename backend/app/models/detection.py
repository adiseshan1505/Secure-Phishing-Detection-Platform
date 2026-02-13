from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app import Base


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False, index=True)
    email_content = Column(String, nullable=True)
    is_phishing = Column(Boolean, nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    rule_based_score = Column(Float, nullable=False)
    ml_based_score = Column(Float, nullable=False)
    detection_method = Column(String(50))
    suspicious_features = Column(JSON, nullable=True)
    url_analysis = Column(JSON, nullable=True)
    ml_prediction_details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    user = relationship("User", back_populates="detection_results")

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "is_phishing": self.is_phishing,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "rule_based_score": self.rule_based_score,
            "ml_based_score": self.ml_based_score,
            "detection_method": self.detection_method,
            "suspicious_features": self.suspicious_features,
            "url_analysis": self.url_analysis,
            "ml_prediction_details": self.ml_prediction_details,
            "timestamp": self.timestamp.isoformat()
        }
