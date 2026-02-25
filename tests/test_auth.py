"""Unit tests for auth.py — no database required."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Set SESSION_SECRET before importing auth so the serializer is initialised
os.environ.setdefault("SESSION_SECRET", "test-secret-for-unit-tests-only-32x")

from auth import (
    SESSION_MAX_AGE,
    create_session_token,
    decode_session_token,
    hash_password,
    verify_password,
)


# ------------------------------------------------------------------
# Password hashing
# ------------------------------------------------------------------

class TestPasswords:
    def test_hash_differs_from_plain(self):
        hashed = hash_password("mysecretpassword")
        assert hashed != "mysecretpassword"

    def test_verify_correct_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_is_bcrypt(self):
        hashed = hash_password("test")
        assert hashed.startswith("$2")

    def test_two_hashes_of_same_password_differ(self):
        """bcrypt uses random salt each time."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2
        # but both verify correctly
        assert verify_password("same-password", h1)
        assert verify_password("same-password", h2)


# ------------------------------------------------------------------
# Session tokens
# ------------------------------------------------------------------

class TestSessionTokens:
    def test_roundtrip(self):
        user_id = "550e8400-e29b-41d4-a716-446655440000"
        token = create_session_token(user_id)
        decoded = decode_session_token(token)
        assert decoded == user_id

    def test_invalid_token_returns_none(self):
        assert decode_session_token("not-a-valid-token") is None

    def test_tampered_token_returns_none(self):
        token = create_session_token("some-user-id")
        tampered = token[:-4] + "xxxx"
        assert decode_session_token(tampered) is None

    def test_empty_token_returns_none(self):
        assert decode_session_token("") is None

    def test_token_is_string(self):
        token = create_session_token("uid-123")
        assert isinstance(token, str)
        assert len(token) > 10

    def test_different_users_different_tokens(self):
        t1 = create_session_token("user-1")
        t2 = create_session_token("user-2")
        assert t1 != t2

    def test_expired_token_returns_none(self, monkeypatch):
        """Simulate token created in the past beyond SESSION_MAX_AGE."""
        import itsdangerous

        # Create a serializer with very short max_age
        from itsdangerous import URLSafeTimedSerializer
        import auth as auth_module

        original_serializer = auth_module._serializer

        # Create token with a timestamp far in the past by monkey-patching time
        token = create_session_token("some-user")

        # Patch decode to use max_age=0 (immediate expiry)
        def always_expired(t, max_age=None):
            raise itsdangerous.SignatureExpired("expired")

        monkeypatch.setattr(auth_module._serializer, "loads", always_expired)

        result = decode_session_token(token)
        assert result is None
