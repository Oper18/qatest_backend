# coding: utf-8

from typing import Optional, List

from pydantic import BaseModel, Field


class AuthResponse(BaseModel):
    access_token: Optional[str] = Field(None, description="access jwt token")
    refresh_token: Optional[str] = Field(None, description="refresh jwt token")


class AccountInfoResponse(BaseModel):
    id: int = Field(description="user pk")
    username: str = Field(description="user username")
    password: str = Field(description="user password")


class Error40xResponse(BaseModel):
    reason: Optional[str] = Field(
        description="information about error or response status"
    )
