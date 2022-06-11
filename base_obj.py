# coding: utf-8

import os
import jwt
import datetime
import json
import base64
from aiofile import async_open

from functools import wraps

from fastapi import status

from settings import (
    SERVER_SECRET,
    ACCESS_TOKEN_LIFETIME,
    REFRESH_TOKEN_LIFETIME,
)
from response_models import Error40xResponse


async def check_token(token):
    try:
        token_info = jwt.decode(token, SERVER_SECRET, algorithms=['HS256'])
    except Exception:
        return status.HTTP_401_UNAUTHORIZED, 'wrong token type', {}
    else:
        try:
            user_info = None
            async with async_open('auth.json', 'r') as f:
                users = await f.read()
                users = json.loads(users)
            for u in users:
                if u["id"] == token_info['user_id']:
                    user_info = u
        except Exception as e:
            return status.HTTP_401_UNAUTHORIZED, 'no user', {}
        else:
            if user_info:
                if user_info["password"] == token_info['password'] and \
                        token_info['expiration_time'] >= datetime.datetime.now().timestamp():
                    return status.HTTP_200_OK, 'user authenticated', user_info
                else:
                    return status.HTTP_401_UNAUTHORIZED, 'token expired', {}
            else:
                return status.HTTP_401_UNAUTHORIZED, 'no user', {}


def login_required(func):
    @wraps(func)
    async def wrapper(**kwargs):
        if kwargs.get('request').user:
            return await func(**kwargs)
        else:
            kwargs['response'].status_code = status.HTTP_401_UNAUTHORIZED
            return Error40xResponse.parse_obj({'reason': kwargs.get('request').auth.get("reason")})
    return wrapper


async def generate_tokens(
    pk: int, username: str, password: str
) -> dict:
    access_token_exp_date = datetime.datetime.now().timestamp() + ACCESS_TOKEN_LIFETIME
    refresh_token_exp_date = datetime.datetime.now().timestamp() + REFRESH_TOKEN_LIFETIME
    access_token = jwt.encode(
        {
            'user_id': pk,
            'username': username,
            'password': password,
            'expiration_time': access_token_exp_date,
        },
        SERVER_SECRET,
        algorithm='HS256'
    )
    refresh_token = jwt.encode(
        {
            'user_id': pk,
            'username': username,
            'password': password,
            'expiration_time': access_token_exp_date,
        },
        SERVER_SECRET,
        algorithm='HS256'
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }
