"""Authentication service for registration, login, and token validation."""

import jwt
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.exc import IntegrityError

from models import User
from schemas.auth import LoginResult, RegisterResult
from security import ALGORITHM, DUMMY_HASH, SECRET_KEY


class EmailAlreadyRegisteredError(Exception):
    """Indicate that an email address is already registered."""

    def __init__(self, email: str):
        """Store the duplicate email address."""
        self.email = email
        super().__init__(f"Email {email} is already registered")


class AuthService:
    """Coordinate persistence, password hashing, and token issuance."""

    def __init__(self, db_session, password_hasher, token_issuer):
        """Store the dependencies used by authentication operations."""
        self.db = db_session
        self.password_hasher = password_hasher
        self.token_issuer = token_issuer

    def register(self, email: str, password: str) -> RegisterResult:
        """Create a unique user account and return its public identity."""
        existing = self.db.query(User).filter(User.email == email).first()
        if existing is not None:
            raise EmailAlreadyRegisteredError(email)

        user = User(
            email=email,
            hashed_password=self.password_hasher.hash(password),
        )
        self.db.add(user)
        try:
            self.db.commit()
        except IntegrityError as error:
            self.db.rollback()
            raise EmailAlreadyRegisteredError(email) from error
        self.db.refresh(user)
        return RegisterResult(id=user.id, email=user.email)

    def login(self, email: str, password: str) -> LoginResult | None:
        """Return a token for valid credentials without leaking account state."""
        user = self.db.query(User).filter(User.email == email).first()
        if user is None:
            self.password_hasher.verify_ignore_result(DUMMY_HASH, password)
            return None

        try:
            self.password_hasher.verify(user.hashed_password, password)
        except VerifyMismatchError:
            return None

        token = self.token_issuer.issue(user.id)
        return LoginResult(user_id=user.id, access_token=token)

    def verify_token(self, token: str) -> int:
        """Decode a valid token and return its user identifier."""
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
