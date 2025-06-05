#!/usr/bin/env python3
"""
Module for authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    Auth class to manage the API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if a path requires authentication.
        For now, returns False, meaning all paths are public.
        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of paths that do not require
                                       authentication.
        Returns:
            bool: True if authentication is required, False otherwise.
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.
        Args:
            request: The Flask request object.
        Returns:
            str: The value of the Authorization header, or None if not found.
        """
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.
        For now, returns None.
        Args:
            request: The Flask request object.
        Returns:
            TypeVar('User'): The User object, or None.
        """
        return None
