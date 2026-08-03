#!/usr/bin/env python3
"""Implement credential encoding, extraction, and secure verification."""

import base64
import hmac

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials


security = HTTPBasic()
password_hasher = PasswordHasher()
stored_users = {
    "admin": password_hasher.hash("s3cret-password"),
}


def encode_credentials(username: str, password: str) -> str:
    """Return Base64 text for the UTF-8 ``username:password`` credential."""
    credentials = f"{username}:{password}".encode("utf-8")
    return base64.b64encode(credentials).decode("utf-8")


def decode_credentials(encoded: str) -> tuple:
    """Decode Base64 credentials and split only on the first colon."""
    decoded = base64.b64decode(encoded).decode("utf-8")
    username, password = decoded.split(":", 1)
    return username, password


def get_current_credentials(
    credentials: HTTPBasicCredentials = Depends(security),
):
    """Return credentials extracted by FastAPI's HTTPBasic dependency."""
    return credentials


def _invalid_credentials():
    """Build the uniform unauthorized error used for every auth failure."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )


def verify_credentials(
    credentials: HTTPBasicCredentials = Depends(security),
) -> str:
    """Verify a submitted password against the stored Argon2 hash."""
    password_hash = stored_users.get(credentials.username)
    if password_hash is None:
        raise _invalid_credentials()
    try:
        password_hasher.verify(password_hash, credentials.password)
    except (VerificationError, InvalidHashError):
        raise _invalid_credentials()
    return credentials.username


def verify_static_token(provided: str, expected: str) -> bool:
    """Compare two static secret values in constant time."""
    return hmac.compare_digest(provided, expected)
