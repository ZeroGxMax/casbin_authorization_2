"""
utils.py
========
Data Models and DAO Layer for User Authentication

This module defines Pydantic models for users, along with Data Access
Objects (DAOs) to manage their storage and retrieval.

Classes:
--------
- User: Represents a user with authentication attributes.
- UserInDB: Extends User to include a hashed password.
- UsersDAO: Provides methods for user authentication and data retrieval.
"""

from typing import Optional
from itertools import filterfalse
from pydantic import BaseModel, Field


class User(BaseModel):
    """
    Represents a user model.

    Attributes:
    - username (str): The username of the user.
    - email (Optional[str]): The user's email address (default: None).
    - full_name (Optional[str]): The user's full name (default: None).
    - disabled (Optional[bool]): Indicates if the user account is disabled (default: None).
    """
    id: str
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    disabled: Optional[bool] = None


class UserInDB(User):
    """
    Extends the User model to include a hashed password for authentication.

    Attributes:
        - hashed_password (str): The securely stored hashed password of the user.
    """

    hashed_password: str


class UsersDAO:
    """
    Data Access Object (DAO) for managing user data and authentication.

    This class provides methods to retrieve user information, hash passwords,
    and decode authentication tokens (for demonstration purposes only).

    Attributes:
    - users_db (dict): A mock database storing user details.
    """

    def __init__(self):
        self.users_db = {
            "supreme": {
                "id": "1",
                "username": "supreme",
                "full_name": "Supreme",
                "email": "supreme@example.com",
                "hashed_password": "fakehashedsecret1",
                "role": "ROLE_ADMIN_ORGANIZATION_1",
                "disabled": False,
            },
            "cto": {
                "id": "2",
                "username": "cto",
                "full_name": "Cto",
                "email": "cto@example.com",
                "hashed_password": "fakehashedsecret2",
                "role": "ROLE_ADMIN_WORKSPACE_1",
                "disabled": False,
            },
            "employee": {
                "id": "3",
                "username": "employee",
                "full_name": "Employee",
                "email": "employee@example.com",
                "hashed_password": "fakehashedsecret3",
                "role": "ROLE_DEV",
                "disabled": False,
            },
            "learner": {
                "id": "4",
                "username": "learner",
                "full_name": "Learner",
                "email": "learner@example.com",
                "hashed_password": "fakehashedsecret4",
                "role": "ROLE_INTERNSHIP",
                "disabled": False,
            },
        }

    def get_user(self, username: str):
        """
        Retrieves a user from the mock database.

        Params:
        - username (str): The username of the user to retrieve.

        Returns:
        - UserInDB: An instance of UserInDB containing the user's details if found.
        - None: If the user does not exist in the database.
        """
        if username in self.users_db:
            user_dict = self.users_db[username]
            return UserInDB(**user_dict)
        return None

    def hash_password(self, password: str):
        """
        Generates a fake hashed password.

        Params:
        - password (str): The plaintext password to hash.

        Returns:
        - str: A fake hashed password.
        """
        return "fakehashed" + password

    def decode_token(self, token):
        """
        Decodes a token to retrieve user information.

        Note: This is a placeholder function and does not provide actual security.

        Params:
        - token (str): The token representing the user's identity.

        Returns:
        - UserInDB: The user corresponding to the given token.
        - None: If the token does not correspond to a valid user.
        """
        user = self.get_user(token)
        return user
