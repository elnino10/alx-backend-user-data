#!/usr/bin/env python3
""" database class module """

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from typing import Dict

from user import Base, User


class DB:
    """DB class"""

    def __init__(self) -> None:
        """Initialize a new DB instance"""
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """adds a user to the database
        args:
            email: email of the user
            hashed_password: hashed password of the user
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """returns first row found in users or raise exceptions
        args:
            kwargs: dictionary of attributes to search for
        """
        if not kwargs or not isinstance(kwargs, dict):
            raise InvalidRequestError
        user = self._session.query(User).filter_by(**kwargs).first()
        if not user:
            raise NoResultFound
        return user

    def update_user(self, user_id: int, **kwargs: Dict) -> None:
        """update user attribute
        args:
            user_id: user id
            kwargs: dictionary of attributes to update
        """
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            setattr(user, key, value)
        self._session.commit()
