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

        # Normalize the incoming path to always end with '/'
        # except for the root path '/' itself
        normalized_path = path
        if not normalized_path.endswith('/'):
            normalized_path += '/'

        # Normalize excluded_paths to always end with '/'
        normalized_excluded_paths = [
            p if p.endswith('/') else p + '/'
            for p in excluded_paths
        ]

        # Check if the normalized path exactly matches or starts with any excluded path
        for excluded_path_normalized in normalized_excluded_paths:
            if normalized_path == excluded_path_normalized:
                return False
            if normalized_path.startswith(excluded_path_normalized):
                return False
            # Special case for root path excluded but request path is empty string or only '/'
            # if excluded_path_normalized == '/' and path == '/':
            #    return False

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
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.
        Args:
            request: The Flask request object.
        Returns:
            TypeVar('User'): The User object, or None.
        """
        return None
