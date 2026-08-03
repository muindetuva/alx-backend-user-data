#!/usr/bin/env python3
"""FastAPI endpoints for secure session authentication."""

from __future__ import annotations

from typing import Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel

from auth import (
    authenticate_user,
    create_session,
    delete_session,
    generate_session_id,
    get_current_user,
    list_user_sessions,
    revoke_session,
    sessions,
    stored_users,
)


app = FastAPI(title="Session Authentication API")


class LoginRequest(BaseModel):
    """Validate credentials supplied to the login endpoint."""

    username: str
    password: str


@app.get("/status")
def application_status() -> dict[str, str]:
    """Return the application's public status."""
    return {"status": "OK"}


@app.get("/health")
def health() -> dict[str, str]:
    """Return the process health signal."""
    return {"health": "alive"}


@app.post("/login")
def login(credentials: LoginRequest, response: Response) -> dict[str, str]:
    """Validate credentials, create a session, and set its secure cookie."""
    username = authenticate_user(credentials.username, credentials.password)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # create_session calls generate_session_id and stores the payload in both
    # Redis and the module-level sessions fallback.
    session_id = create_session(stored_users[username]["user_id"])
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return {"message": "Logged in"}


@app.get("/profile")
def profile(current_user: dict = Depends(get_current_user)) -> dict:
    """Return the identity represented by the active session."""
    return current_user


@app.post("/logout")
def logout(
    response: Response,
    session_id: Optional[str] = Cookie(default=None),
) -> dict[str, str]:
    """Invalidate the server session and clear the client cookie."""
    if session_id:
        delete_session(session_id)
    response.delete_cookie("session_id")
    return {"message": "Logged out"}


@app.get("/sessions")
def active_sessions(
    current_user: dict = Depends(get_current_user),
) -> dict[str, list[dict]]:
    """List the current user's active sessions."""
    return {
        "sessions": list_user_sessions(current_user["user_id"]),
    }


@app.post("/sessions/{session_id}/revoke")
def revoke_active_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke one session after verifying that it belongs to the user."""
    owned_session_ids = {
        item["session_id"]
        for item in list_user_sessions(current_user["user_id"])
    }
    if session_id not in owned_session_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )
    revoke_session(session_id)
    return {"message": "Session revoked"}
