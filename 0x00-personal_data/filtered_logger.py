#!/usr/bin/env python3
""" filtered logger module"""

import logging
import re


def filter_datum(fields, redaction, message, separator):
    """returns the log message obfuscated
    args:
        fields: list of strings representing all fields to obfuscate
        redaction: a string representing by what the field will be obfuscated
        message: a string representing the log line
        separator: a string representing by which character is separating all
            fields in the log line (message)
    """
    for field in fields:
        message = re.sub(
            r"{}=(.*?){}".format(field, separator),
            "{}={}{}".format(field, redaction, separator),
            message,
        )
    return message


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: list[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """filter values in incoming log records using filter_datum()
        args:
            record: a log record
        """
        return filter_datum(
            self.fields, self.REDACTION, super().format(record), self.SEPARATOR
        )


def get_logger() -> logging.Logger:
    """returns a logging.Logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=("name", "email", "phone")))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> logging.Logger:
    """returns a logging.Logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=("password", "ssn")))
    logger.addHandler(stream_handler)

    return logger


def main() -> None:
    """main function"""
    db = get_db()
    db.info("SELECT * FROM users;")


if __name__ == "__main__":
    main()
