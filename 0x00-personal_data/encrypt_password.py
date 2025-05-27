#!/usr/bin/env python3
"""
Module for password hashing using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt with automatic salting.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verify a password against a given hashed password.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
