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
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        # Ensure path ends with a slash for consistent comparison
        # if it doesn't already, except for root '/'
        if not path.endswith('/'):
            normalized_path = path + '/'
        else:
            normalized_path = path

        # Check if the normalized path is in the excluded_paths
        for excluded_path in excluded_paths:
            if excluded_path.endswith('/'):
                # Handle /status and /status/ when /status/ is excluded
                if normalized_path == excluded_path:
                    return False
                # Handle cases like /admin/foo/ and /admin/ (prefix matching)
                if normalized_path.startswith(excluded_path):
                    return False
            # Fallback for paths that might not end with '/' in excluded_paths
            # (though the prompt says they will end with '/')
            # This makes it more robust.
            elif path == excluded_path:
                return False

        return True

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
