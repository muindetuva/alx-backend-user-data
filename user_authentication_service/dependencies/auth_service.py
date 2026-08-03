"""Dependency wiring for AuthService."""

from fastapi import Depends

from database import get_db
from security import PasswordHasherAdapter, TokenIssuer
from services.auth import AuthService


def get_auth_service(db_session=Depends(get_db)) -> AuthService:
    """Return a fully wired authentication service."""
    return AuthService(db_session, PasswordHasherAdapter(), TokenIssuer())
