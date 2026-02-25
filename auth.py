"""Authentication helpers: bcrypt + signed session cookies + FastAPI dependencies."""

import os

from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from passlib.context import CryptContext

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

COOKIE_NAME = "session"
SESSION_MAX_AGE = 60 * 60 * 8  # 8 hours

_SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me-in-production")
_serializer = URLSafeTimedSerializer(_SESSION_SECRET, salt="session")


# ------------------------------------------------------------------
# Password helpers
# ------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


# ------------------------------------------------------------------
# Session token helpers
# ------------------------------------------------------------------

def create_session_token(user_id: str) -> str:
    """Sign user_id with itsdangerous. Returns URL-safe string."""
    return _serializer.dumps(user_id)


def decode_session_token(token: str) -> str | None:
    """Return user_id string, or None if invalid/expired."""
    try:
        return _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


# ------------------------------------------------------------------
# FastAPI dependencies
# ------------------------------------------------------------------

async def get_current_user(request: Request) -> dict:
    """Read cookie → decode → fetch user from DB. Raises 401 if unauthenticated."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user_id = decode_session_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Session expired")

    db = request.app.state.db
    user = await db.get_user_by_id(user_id)
    if user is None or not user["enabled"]:
        raise HTTPException(status_code=401, detail="User not found or disabled")

    return dict(user)


def require_operator(user: dict = Depends(get_current_user)) -> dict:
    """Allow operator and admin roles."""
    if user["role"] not in ("operator", "admin"):
        raise HTTPException(status_code=403, detail="Operator role required")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Allow admin role only."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user
