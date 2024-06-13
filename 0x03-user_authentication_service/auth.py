#!/usr/bin/env python3
""" authentication module """

import bcrypt
from db import DB
from user import User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """hashes a password"""
    password = password.encode("utf-8")
    hashed_passwd = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_passwd


def _generate_uuid() -> str:
    """generates a uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register a user"""
        user = self._db.find_user_by(email=email)
        if user:
            raise ValueError(f"User {email} already exists")
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self._db.add_user(email, hashed)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """validate login credentials"""
        try:
            user = self._db.find_user_by(email=email)
            password_match = bcrypt.checkpw(
                password.encode("utf-8"), user.hashed_password
            )
            return password_match
        except Exception:
            return False
