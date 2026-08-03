#!/usr/bin/env python3
"""Expose public and Basic-Auth-protected FastAPI routes."""

from fastapi import Depends, FastAPI

from auth import verify_credentials
from routers.admin import admin_router


app = FastAPI(title="Basic Authentication API")
app.include_router(admin_router)


@app.get("/")
def root():
    """Return a public welcome message for the API."""
    return {"message": "Welcome to the Basic Auth API"}


@app.get("/status")
def api_status():
    """Return a public application status response."""
    return {"status": "OK"}


@app.get("/health")
def health():
    """Return a public application health response."""
    return {"health": "alive"}


@app.get("/admin/dashboard")
def admin_dashboard(username: str = Depends(verify_credentials)):
    """Return the dashboard response for an authenticated administrator."""
    return {"message": "Welcome", "user": username}
