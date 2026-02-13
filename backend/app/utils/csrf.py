from fastapi import Request
import hashlib
import time

csrf_tokens = {}


def generate_csrf_token(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    token = hashlib.sha256(f"{client_host}{time.time()}".encode()).hexdigest()
    csrf_tokens[token] = time.time()
    return token


def validate_csrf_token(token: str) -> bool:
    if token not in csrf_tokens:
        return False
    token_age = time.time() - csrf_tokens[token]
    if token_age > 3600:
        del csrf_tokens[token]
        return False
    return True
