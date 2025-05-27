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
