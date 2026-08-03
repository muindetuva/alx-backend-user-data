"""FastAPI entry point for the complete user authentication service."""

from fastapi import Depends, FastAPI, HTTPException, Response, status

from database import Base, engine, get_db
from dependencies.auth_service import get_auth_service
from dependencies.current_user import (
    get_current_user,
    require_admin,
    require_permission,
)
from models import User
from schemas.auth import LoginRequest, LoginResult, RegisterRequest, RegisterResult
from services.auth import AuthService, EmailAlreadyRegisteredError


Base.metadata.create_all(bind=engine)
app = FastAPI(title="User Authentication Service")

reports = {1: {"id": 1, "owner_id": 1, "title": "Monthly summary"}}


@app.get("/status")
def service_status() -> dict[str, str]:
    """Return the public service status."""
    return {"status": "OK"}


@app.get("/health")
def health() -> dict[str, str]:
    """Return the public health response."""
    return {"health": "alive"}


@app.post("/register", response_model=RegisterResult, status_code=201)
def register(
    request: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> RegisterResult:
    """Register a new account or return HTTP 409 for a duplicate email."""
    try:
        return auth_service.register(request.email, request.password)
    except EmailAlreadyRegisteredError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/login", response_model=LoginResult)
def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> LoginResult:
    """Return an access token for valid credentials."""
    result = auth_service.login(request.email, request.password)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return result


@app.get("/me")
def me(current_user=Depends(get_current_user)) -> dict:
    """Return the current authenticated user's identity."""
    return {"id": current_user.id, "email": current_user.email}


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    admin=Depends(require_admin),
    db=Depends(get_db),
) -> Response:
    """Allow an administrator to delete an existing user."""
    del admin
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.patch("/reports/{report_id}")
def update_report(
    report_id: int,
    title: str,
    current_user=Depends(require_permission("reports:write")),
) -> dict:
    """Require report-write permission plus ownership or admin status."""
    report = reports.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report["owner_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You do not own this report")
    report["title"] = title
    return report
