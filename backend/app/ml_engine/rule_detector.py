import re
from urllib.parse import urlparse


class RuleBasedDetector:
    SUSPICIOUS_KEYWORDS = [
        "verify", "confirm", "update", "click here", "urgent", "action required",
        "suspended", "alert", "secure", "bank", "paypal", "amazon", "apple"
    ]
    PHISHING_KEYWORDS = ["phishing", "scam", "fake", "malware"]

    @staticmethod
    def analyze_url(url):
        features = {}
        score = 0

        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path

            url_length = len(url)
            features["url_length"] = url_length
            if url_length > 75:
                score += 20
                features["suspicious_length"] = True

            if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
                score += 30
                features["ip_based_url"] = True

            if re.search(r"[@!#$%^&*()_+=\[\]{};':\",.< >?/\\|`~-]", domain):
                score += 25
                features["special_chars_in_domain"] = True

            subdomains = domain.split(".")
            if len(subdomains) > 3:
                score += 15
                features["multiple_subdomains"] = True

            if "-" in domain:
                score += 10
                features["hyphen_in_domain"] = True

            features["has_https"] = parsed.scheme == "https"
            if parsed.scheme != "https":
                score += 10

            legitimate_domains = [
                "google.com", "facebook.com", "amazon.com", "github.com",
                "microsoft.com", "apple.com", "paypal.com"
            ]
            if any(legit in domain for legit in legitimate_domains):
                score = max(0, score - 20)
                features["legitimate_domain_pattern"] = True

            if any(keyword in url.lower() for keyword in ["password", "login", "verify", "confirm", "update"]):
                score += 15
                features["suspicious_path_keywords"] = True

            features["score"] = min(100, score)

        except Exception as e:
            features["error"] = str(e)
            features["score"] = 50

        return features

    @staticmethod
    def analyze_email(email_content):
        features = {}
        score = 0

        if not email_content:
            return features

        email_lower = email_content.lower()

        urgency_keywords = [
            "urgent", "immediately", "action required", "verify now", "confirm identity",
            "suspicious activity", "unusual login", "click here"
        ]
        urgency_count = sum(1 for keyword in urgency_keywords if keyword in email_lower)
        if urgency_count > 0:
            score += urgency_count * 15
            features["urgency_keywords"] = urgency_count

        spelling_errors = ["recieve", "occured", "seperete", "bussiness", "adress"]
        error_count = sum(1 for error in spelling_errors if error in email_lower)
        if error_count > 0:
            score += error_count * 10
            features["spelling_errors"] = error_count

        if any(greeting in email_lower for greeting in ["dear user", "dear customer", "dear member"]):
            score += 15
            features["generic_greeting"] = True

        urls = re.findall(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            email_content
        )
        if urls:
            features["urls_found"] = len(urls)
            score += len(urls) * 10

        phishing_keywords = [
            "verify account", "confirm password", "update payment", "unusual activity",
            "compromised", "unauthorized access"
        ]
        phishing_count = sum(1 for keyword in phishing_keywords if keyword in email_lower)
        if phishing_count > 0:
            score += phishing_count * 20
            features["phishing_keywords"] = phishing_count

        features["score"] = min(100, score)

        return features

    @staticmethod
    def detect(url, email_content=None):
        url_features = RuleBasedDetector.analyze_url(url)
        url_score = url_features.get("score", 0)

        email_features = {}
        email_score = 0
        if email_content:
            email_features = RuleBasedDetector.analyze_email(email_content)
            email_score = email_features.get("score", 0)

        if email_content:
            final_score = (url_score * 0.6) + (email_score * 0.4)
        else:
            final_score = url_score

        is_phishing = final_score >= 50

        return {
            "score": final_score,
            "is_phishing": is_phishing,
            "confidence": min(95, abs(final_score - 50) + 50),
            "url_features": url_features,
            "email_features": email_features,
            "detection_method": "rule_based"
        }
