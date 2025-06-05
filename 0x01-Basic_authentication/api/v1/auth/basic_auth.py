#!/usr/bin/env python3
"""
Basic Authentication module
"""
import base64
from api.v1.auth.auth import Auth
from typing import Optional


class BasicAuth(Auth):
    """
    BasicAuth class that inherits from Auth.
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str
                                            ) -> Optional[str]:
        """
        Extracts the Base64 encoded part of the Authorization header for
        Basic Authentication.

        Args:
            authorization_header (str): The full Authorization header string.

        Returns:
            str: The Base64 encoded credentials string, or None if invalid.
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        # Return the part after "Basic "
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> Optional[str]:
        """
        Decodes a Base64 encoded string.

        Args:
            base64_authorization_header (str): The Base64 encoded string.

        Returns:
            str: The decoded string as UTF-8, or None if decoding fails or
                 input is invalid.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            # Base64 decode expects bytes, so encode the string first
            decoded_bytes = base64.b64decode(base64_authorization_header)
            # Then decode the bytes to a UTF-8 string
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            # Catch Base64 decoding errors (binascii.Error)
            # and UTF-8 decoding errors (UnicodeDecodeError)
            return None
