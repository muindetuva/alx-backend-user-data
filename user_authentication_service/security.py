"""Password hashing and JWT token issuance."""

import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from settings import get_settings


settings = get_settings()
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = settings.access_token_expire_seconds


class PasswordHasherAdapter:
    """Expose the password operations required by AuthService."""

    def __init__(self):
        """Create the underlying Argon2 password hasher."""
        self._hasher = PasswordHasher()

    def hash(self, password: str) -> str:
        """Return an Argon2 password hash."""
        return self._hasher.hash(password)

    def verify(self, hashed_password: str, password: str) -> bool:
        """Verify a password and raise VerifyMismatchError on mismatch."""
        return self._hasher.verify(hashed_password, password)

    def verify_ignore_result(self, hashed_password: str, password: str) -> None:
        """Perform a verification while deliberately ignoring its outcome."""
        try:
            self._hasher.verify(hashed_password, password)
        except VerifyMismatchError:
            pass


password_hasher = PasswordHasherAdapter()
DUMMY_HASH = password_hasher.hash("dummy-password-for-timing")


class TokenIssuer:
    """Issue time-limited JSON Web Tokens for authenticated users."""

    def issue(self, user_id: int) -> str:
        """Return a signed JWT containing sub, iat, and exp claims."""
        now = int(time.time())
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
