#!/usr/bin/env python3
""" encrypt password module"""

import bcrypt


def hash_password(password: str) -> bytes:
    """returns a salted, hashed password, which is a byte string"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """returns a boolean indicating whether or not the provided password
    matches the hashed password"""
    return bcrypt.checkpw(password.encode(), hashed_password)
