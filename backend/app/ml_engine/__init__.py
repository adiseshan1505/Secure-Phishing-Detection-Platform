from app.ml_engine.rule_detector import RuleBasedDetector
from app.ml_engine.ml_detector import MLDetector


class HybridDetector:
    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector()

    def detect(self, url, email_content=None):
        rule_result = self.rule_detector.detect(url, email_content)
        rule_score = rule_result["score"]

        ml_result = self.ml_detector.predict(url)
        ml_score = ml_result["score"]

        hybrid_score = (rule_score * 0.5) + (ml_score * 0.5)
        is_phishing = hybrid_score >= 50
        confidence = self._calculate_confidence(rule_score, ml_score, hybrid_score)

        return {
            "url": url,
            "is_phishing": is_phishing,
            "risk_score": hybrid_score,
            "confidence": confidence,
            "rule_based_score": rule_score,
            "ml_based_score": ml_score,
            "detection_method": "hybrid",
            "rule_features": rule_result.get("url_features", {}),
            "email_features": rule_result.get("email_features", {}),
            "ml_details": {
                "probability_phishing": ml_result.get("probability_phishing", 0),
                "probability_legitimate": ml_result.get("probability_legitimate", 0)
            },
            "suspicious_features": self._extract_suspicious_features(rule_result, ml_result)
        }

    @staticmethod
    def _calculate_confidence(rule_score, ml_score, hybrid_score):
        agreement = 1 - (abs(rule_score - ml_score) / 100)
        distance_from_boundary = abs(hybrid_score - 50) / 50
        confidence = ((agreement * 0.4) + (distance_from_boundary * 0.6)) * 100
        return min(100, max(0, confidence))

    @staticmethod
    def _extract_suspicious_features(rule_result, ml_result):
        features = []
        rule_features = rule_result.get("url_features", {})
        for key, value in rule_features.items():
            if value is True or (isinstance(value, (int, float)) and value > 0 and key != "score"):
                features.append(key)
        return features
