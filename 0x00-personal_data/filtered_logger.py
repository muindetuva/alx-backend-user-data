#!/usr/bin/env python3
"""
Module for filtering sensitive data from log messages.
"""

import re
import logging
from typing import List, Tuple


PII_FIELDS: Tuple[str, ...] = ("name", "email", "phone", "ssn", "password")


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


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the formatter with fields to redact."""
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format and redact sensitive fields in log messages."""
        original = record.getMessage()
        redacted = filter_datum(
            self.fields, self.REDACTION, original, self.SEPARATOR
        )
        record.msg = redacted
        return super().format(record)


def get_logger() -> logging.Logger:
    """Creates and returns a configured logger for user data."""

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger.addHandger(stream_handler)

    return logger
