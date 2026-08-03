#!/usr/bin/env python3
"""Expose admin routes protected by a router-level Basic Auth dependency."""

from fastapi import APIRouter, Depends

from auth import verify_credentials


admin_router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(verify_credentials)],
)


@admin_router.get("/reports")
def reports():
    """Return the protected collection of administrative reports."""
    return {"reports": []}


@admin_router.get("/users")
def users():
    """Return the protected collection of administrative users."""
    return {"users": []}
