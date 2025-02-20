"""
main.py
"""

from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.responses import RedirectResponse

# from pydantic import BaseModel
from settings import MODEL_CONF_PATH, POLICY_CSV_PATH
import casbin
from utils import User, UsersDAO, DeleteJobRequest, CreateTaskRequest, CreateCatalogRequest
from utils import *
import redis
from loguru import logger
from urllib.parse import unquote
import json
from constants import AccessLevel
from services.auth_service import *
from routes import jobs, catalogs, schemas, tables, bucket, file

app = FastAPI()
app.include_router(jobs.router)
app.include_router(catalogs.router)
app.include_router(schemas.router)
app.include_router(tables.router)
app.include_router(bucket.router)
app.include_router(file.router)

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticates a user and provides an OAuth2 access token.

    This endpoint verifies the user's credentials by checking the username and hashed password.
    If successful, it returns an access token which can be used to access protected routes.

    Params:
    - form_data (OAuth2PasswordRequestForm): The user's credentials (username and password).

    Returns:
    - dict: A dictionary containing the `access_token` and `token_type` if authentication is successful.

    Raises:
    - HTTPException: If the username or password is incorrect, a 400 Bad Request error is raised.
    """
    user = users_dao.get_user(form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    hashed_password = users_dao.hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    """
    Redirects the user to the API documentation.

    This endpoint is used to redirect requests to the root path to the `/docs` endpoint,
    which contains the automatically generated API documentation.

    Returns:
    - RedirectResponse: Redirects the request to the `/docs` page.
    """
    response = RedirectResponse(url="/docs")
    return response
    




