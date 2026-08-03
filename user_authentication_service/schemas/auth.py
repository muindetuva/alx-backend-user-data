"""Validation schemas for registration and login."""

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Validate a new account registration request."""

    email: EmailStr
    password: str = Field(min_length=10, description="At least 10 characters")


class LoginRequest(BaseModel):
    """Validate credentials submitted for login."""

    email: EmailStr
    password: str


class RegisterResult(BaseModel):
    """Describe a successfully registered account."""

    id: int
    email: EmailStr


class LoginResult(BaseModel):
    """Describe a successful login and issued access token."""

    user_id: int
    access_token: str
    token_type: str = "bearer"
