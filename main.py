from typing import Optional, Any, Union

import json
from aiofile import async_open

from fastapi import FastAPI, status, Request, Response

from base_obj import generate_tokens, login_required, check_token

from request_models import Auth
from response_models import (
    AuthResponse,
    Error40xResponse,
    AccountInfoResponse,
)

app = FastAPI()

@app.middleware("http")
async def auth_middleware(request: Request, call_next, *args, **kwargs):
    request.scope["user"] = None
    request.scope["auth"] = {"status": False, "reason": ""}
    if request.headers.get("authorization"):
        try:
            user_type, token = request.headers.get("authorization").split(' ')
            code, reason, user_info = await check_token(token=token)
        except Exception as e:
            request.scope["auth"]["reason"] = "wrong token type"
        else:
            request.scope["user"] = user_info
            request.scope["auth"]["reason"] = reason
    else:
        request.scope["auth"]["reason"] = "no token"

    response = await call_next(request)

    return response


@app.post("/api/auth/")
async def auth(
    auth: Auth,
    request: Request,
    response: Response,
    status_code: Optional[Any] = status.HTTP_200_OK,
) -> Union[Auth, Error40xResponse]:
    for s in "/?*$&":
        if s in auth.username or s in auth.password:
            raise AttributeError
    async with async_open('auth.json', 'r') as f:
        users = await f.read()
        users = json.loads(users)

    for u in users:
        if auth.username == u["username"] and auth.password == u["password"]:
            creds = await generate_tokens(
                pk=u["id"],
                username=u["username"],
                password=u["password"],
            )
            return AuthResponse.parse_obj(creds)
    response.status_code = status.HTTP_401_UNAUTHORIZED
    return Error40xResponse.parse_obj({"reason": "unknown credentials"})


@app.get("/api/account/info/")
@login_required
async def account_info(
    request: Request,
    response: Response,
    status_code: Optional[Any] = status.HTTP_200_OK,
) -> Union[AccountInfoResponse, Error40xResponse]:
    return AccountInfoResponse.parse_obj(request.user)
