from fastapi import Request
import re


def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def validate_username(username):
    if len(username) < 3 or len(username) > 50:
        return False
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False
    return True


def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain special character"
    return True, "Password is valid"


def validate_url(url):
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    return re.match(pattern, url, re.IGNORECASE) is not None


def sanitize_string(s):
    return re.sub(r"[<>\"'%;()&+]", "", s)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0]
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")
