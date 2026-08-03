#!/usr/bin/env python3
"""
Module for filtering sensitive data from log messages.
"""

import re
import os
import mysql.connector
from mysql.connector.connection import MySQLConnection
import logging
from typing import List, Tuple


PII_FIELDS: Tuple[str, ...] = ("name", "email", "phone", "ssn", "password")


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Obfuscate selected field values in a structured log message."""
    pattern = r"({})=.*?{}".format("|".join(fields), separator)
    return re.sub(pattern, r"\1={}{}".format(redaction, separator), message)


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
        message = super().format(record)
        return filter_datum(
            self.fields, self.REDACTION, message, self.SEPARATOR
        )


def get_logger() -> logging.Logger:
    """Creates and returns a configured logger for user data."""

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))

    if not logger.handlers:
        logger.addHandler(stream_handler)

    return logger


def get_db() -> MySQLConnection:
    """Connect to MySQL db using env variables and return connection object"""
    return mysql.connector.connect(
        host=os.environ.get("PERSONAL_DATA_DB_HOST", "localhost"),
        user=os.environ.get("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.environ.get("PERSONAL_DATA_DB_PASSWORD", ""),
        database=os.environ.get("PERSONAL_DATA_DB_NAME")
    )


def main() -> None:
    """
    Obtain a database connection, retrieve all rows in the users table,
    and log each row with redacted PII fields.
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users;")
    fields = [desc[0] for desc in cursor.description]  # column names
    logger = get_logger()

    for row in cursor:
        row_data = "; ".join(
            f"{field}={value}" for field, value in zip(fields, row)
        ) + ";"
        logger.info(row_data)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
