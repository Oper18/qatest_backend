# coding: utf-8

from typing import Optional, List

from pydantic import BaseModel, Field


class Auth(BaseModel):
    username: str = Field(description="username of user")
    password: str = Field(description="user password")
