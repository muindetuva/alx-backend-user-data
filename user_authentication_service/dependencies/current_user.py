"""JWT validation and role/permission authorization dependencies."""

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from database import get_db
from models import User
from security import SECRET_KEY


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

PERMISSIONS_BY_ROLE = {
    "admin": {"users:delete", "reports:read", "reports:write"},
    "analyst": {"reports:read", "reports:write"},
    "user": {"reports:read"},
}


def get_current_user_id(token: str = Depends(oauth2_scheme)) -> int:
    """Validate a JWT and return its subject as an integer user id."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from error
    except jwt.InvalidTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from error

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return int(user_id)


def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db=Depends(get_db),
):
    """Resolve an active user record from a valid access token."""
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    return user


def require_admin(current_user=Depends(get_current_user)):
    """Return an administrator or reject an under-privileged user."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="This action requires admin privileges",
        )
    return current_user


def require_permission(permission: str):
    """Build a dependency requiring one data-driven permission string."""
    def dependency(current_user=Depends(get_current_user)):
        allowed = PERMISSIONS_BY_ROLE.get(current_user.role, set())
        if permission not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Missing required permission: {permission}",
            )
        return current_user

    return dependency
