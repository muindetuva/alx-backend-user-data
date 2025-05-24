#!/usr/bin/env python3
"""
Module for filtering sensitive data from log messages.
"""

import re
from typing import List


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Obfuscates the values of specified fields in a log message.
    """
    pattern = fr"({'|'.join(fields)})=.*?{re.escape(separator)}"
    return re.sub(
        pattern,
        lambda m: f"{m.group(1)}={redaction}{separator}",
        message
    )
