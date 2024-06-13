#!/usr/bin/env python3
""" authentication module """

import bcrypt
from db import DB
from user import User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """hashes a password
    args:
        password: password to hash
    """
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
        """register a user
        args:
            email: email of the user
            password: password of the user
        """
        user = self._db.find_user_by(email=email)
        if user:
            raise ValueError(f"User {email} already exists")
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self._db.add_user(email, hashed)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """validate login credentials
        args:
            email: email of the user
            password: password of the user
        """
        try:
            user = self._db.find_user_by(email=email)
            password_match = bcrypt.checkpw(
                password.encode("utf-8"), user.hashed_password
            )
            return password_match
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """creates session id and returns it
        args:
            email: email of the user
        """
        user = self._db.find_user_by(email=email)
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id) -> User:
        """return a user based on session id
        args:
            session_id: session id
        """
        if not session_id:
            return None
        user = self._db.find_user_by(session_id=session_id)
        if not user:
            return None
        return user

    def destroy_session(self, user_id: str) -> None:
        """destroys a session
        args:
            user_id: user id of the session to be destroyed
        """
        user = self._db.find_user_by(id=user_id)
        setattr(user, user.session_id, None)
        return

    def get_reset_password_token(self, email: str) -> str:
        """generates token for resseting password
        args:
            email: user's registered email
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """updates user password
        args:
            reset_token: token sent to user's email
            password: new user password
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if not user:
            raise ValueError
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
