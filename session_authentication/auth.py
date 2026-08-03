#!/usr/bin/env python3
"""Session creation, persistence, resolution, expiry, and revocation."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

import redis
from fastapi import Cookie, HTTPException, status


SESSION_TTL_SECONDS = 30 * 60
IDLE_TIMEOUT_SECONDS = 30 * 60
ABSOLUTE_TIMEOUT_SECONDS = 24 * 60 * 60

redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True,
    socket_connect_timeout=1,
    socket_timeout=1,
)

# The dictionary remains useful as a local development fallback and preserves
# the in-memory progression introduced before the Redis-backed implementation.
sessions: dict[str, dict] = {}

stored_users: dict[str, dict] = {
    "demo": {
        "user_id": 1,
        "password_hash": (
            "41bd876b085d6031cb0e04de35b88d77f83a4ba39f879fee40805ac19e356023"
        ),
    }
}


def now() -> float:
    """Return the current Unix timestamp."""
    return time.time()


def generate_session_id() -> str:
    """Return a cryptographically secure URL-safe session identifier."""
    return secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    """Return a SHA-256 digest for comparison with the stored demo hash."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def authenticate_user(username: str, password: str) -> Optional[str]:
    """Return the username when its supplied password is valid."""
    user = stored_users.get(username)
    if user is None:
        return None
    supplied_hash = hash_password(password)
    if not hmac.compare_digest(supplied_hash, user["password_hash"]):
        return None
    return username


def session_key(session_id: str) -> str:
    """Return the Redis key used for a session identifier."""
    return f"session:{session_id}"


def username_for(user_id: int) -> Optional[str]:
    """Find the username associated with an integer user id."""
    for username, user in stored_users.items():
        if user["user_id"] == user_id:
            return username
    return None


def create_session(user_id: int) -> str:
    """Create and persist a session, returning its opaque identifier."""
    session_id = generate_session_id()
    payload = {
        "user_id": user_id,
        "username": username_for(user_id),
        "created_at": now(),
    }
    sessions[session_id] = payload
    try:
        redis_client.setex(
            session_key(session_id), SESSION_TTL_SECONDS, json.dumps(payload)
        )
        redis_client.sadd(f"user_sessions:{user_id}", session_id)
    except redis.RedisError:
        # The in-memory fallback keeps local development deterministic when a
        # Redis daemon is unavailable. Production deployments should require
        # Redis and surface connection failures through monitoring.
        pass
    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """Return a decoded session from Redis or the local fallback."""
    try:
        raw = redis_client.get(session_key(session_id))
    except redis.RedisError:
        raw = None
    if raw:
        payload = json.loads(raw)
        sessions[session_id] = payload
        return payload
    return sessions.get(session_id)


def delete_session(session_id: str) -> None:
    """Delete a session and remove it from its per-user index."""
    payload = get_session(session_id)
    sessions.pop(session_id, None)
    try:
        redis_client.delete(session_key(session_id))
        if payload is not None:
            redis_client.srem(
                f"user_sessions:{payload['user_id']}", session_id
            )
    except redis.RedisError:
        pass


def touch_session(session_id: str) -> Optional[dict]:
    """Enforce the absolute timeout and renew a valid session's idle TTL."""
    session = get_session(session_id)
    if session is None:
        return None
    if now() - session["created_at"] > ABSOLUTE_TIMEOUT_SECONDS:
        delete_session(session_id)
        return None
    try:
        redis_client.expire(session_key(session_id), IDLE_TIMEOUT_SECONDS)
    except redis.RedisError:
        pass
    return session


def get_current_user(
    session_cookie: Optional[str] = Cookie(default=None, alias="session_id"),
) -> dict:
    """Resolve and return the authenticated identity from a session cookie."""
    if session_cookie is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    session = get_session(session_cookie)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    session = touch_session(session_cookie)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return session


def list_user_sessions(user_id: int) -> list[dict]:
    """Return every active session belonging to a user."""
    try:
        session_ids = redis_client.smembers(f"user_sessions:{user_id}")
    except redis.RedisError:
        session_ids = {
            session_id
            for session_id, payload in sessions.items()
            if payload.get("user_id") == user_id
        }
    active_sessions = []
    for session_id in session_ids:
        payload = get_session(session_id)
        if payload is not None:
            active_sessions.append({"session_id": session_id, **payload})
    return active_sessions


def revoke_session(session_id: str) -> None:
    """Revoke one active session."""
    delete_session(session_id)
