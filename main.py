"""
main.py
"""

from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.responses import RedirectResponse

# from pydantic import BaseModel
from settings import MODEL_CONF_PATH, POLICY_CSV_PATH
import casbin
from utils import User, UsersDAO
import redis
from loguru import logger
from urllib.parse import unquote

app = FastAPI()
users_dao = UsersDAO()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
redis_cli = redis.Redis(host="localhost", port=6379, decode_responses=True)
print(redis_cli.ping())

casbin_enforcer = casbin.Enforcer(MODEL_CONF_PATH, POLICY_CSV_PATH, True)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Authentication Module for FastAPI with OAuth2

    This module provides an asynchronous function to retrieve the current user based on a
    provided OAuth2 token. The function verifies the token, decodes user information, and
    raises an HTTP 401 Unauthorized exception if the authentication fails.

    Params:
    - token (str): The OAuth2 token provided in the request header.

    Returns:
    - A dictionary containing user details if authentication is successful.
    """

    user = users_dao.decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(curr_user: User = Depends(get_current_user)):
    """
    Verifies that the current user is active.

    This function checks whether the user account is disabled. If the user is disabled,
    it raises a 400 HTTP exception indicating the user is inactive.

    Params:
    - curr_user (User): The current authenticated user, retrieved via OAuth2 token.

    Returns:
    - User: The current active user if the account is not disabled.

    Raises:
    - HTTPException: If the user's account is disabled, a 400 Bad Request error is raised.
    """
    if curr_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return curr_user


async def get_current_user_authorization_on_redis(
    req: Request, curr_user: User = Depends(get_current_active_user)
):
    """
    Verifies that the current user has the necessary authorization to access redis resource.

    This function uses the Casbin Enforcer to check if the current user is authorized to
    perform the requested action on the specified resource. It checks the user's role and
    the action against a policy defined in `policy.csv`.

    Params:
    - req (Request): The incoming request object that contains the URL and HTTP method.
    - curr_user (User): The currently authenticated user, retrieved via OAuth2 token and
    validated for activity.

    Returns:
    - User: The authenticated user if authorization is granted.

    Raises:
    - HTTPException: If the user is not authorized to perform the requested action, a 401
    Unauthorized error is raised.
    """
    key = req.query_params.get("key") or unquote(req.url.path).removeprefix("/redis/")
    if not key:
        raise HTTPException(status_code=400, detail="Key is required.")
    logger.warning(f"key: {key}")
    sub = curr_user.username
    obj = key
    act = req.method
    eft = casbin_enforcer.enforce(sub, obj, act)
    if not eft:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Method not authorized for this user",
        )
    return curr_user


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


@app.post("/redis")
async def store_redis_key(
    key: str, value, curr_user: User = Depends(get_current_user_authorization_on_redis)
):
    """
    This function stores a key-value pair in Redis. If the key already exists, an error is raised.

    Params:
    - key (str): The Redis key to be created.
    - value (str): The value to store.
    - curr_user (User): The authorized user retrieved via OAuth2.

    Returns:
    - dict: A success message confirming key creation.

    Raises:
    - HTTPException: If the key already exists, a 400 Bad Request error is raised.
    """
    # Check if the key already exists
    if redis_cli.exists(key):
        raise HTTPException(
            status_code=400, detail=f"Key '{key}' already exists in Redis."
        )

    # Set the new key-value pair
    redis_cli.set(key, value)
    casbin_enforcer.add_policy(curr_user.username, key, ".*", "allow")
    casbin_enforcer.save_policy()
    return {"message": f"Key '{key}' successfully created."}

@app.get("/redis")
async def retrieve_redis_key(
    key: str, curr_user: User = Depends(get_current_user_authorization_on_redis)
):
    """
    This function retrieves the value of a given Redis key. If the key does not exist, an error is raised.

    Params:
    - key (str): The Redis key to retrieve.
    - curr_user (User): The authorized user retrieved via OAuth2.

    Returns:
    - dict: A dictionary containing the key and its value.

    Raises:
    - HTTPException: If the key does not exist, a 404 Not Found error is raised.
    """
    if not redis_cli.exists(key):
        raise HTTPException(
            status_code=404, detail=f"Key '{key}' does not exist in Redis."
        )
    return {"key": key, "value": redis_cli.get(key)}

@app.put("/redis/{key}")
async def update_redis_key(
    key: str, value: str, curr_user: User = Depends(get_current_user_authorization_on_redis)
):
    """
    This function updates the value of an existing Redis key. If the key does not exist, an error is raised.

    Params:
    - key (str): The Redis key to be updated.
    - value (str): The new value to update.
    - curr_user (User): The authorized user retrieved via OAuth2.

    Returns:
    - dict: A success message confirming the update.

    Raises:
    - HTTPException: If the key does not exist, a 404 Not Found error is raised.
    """
    if not redis_cli.exists(key):
        raise HTTPException(
            status_code=404, detail=f"Key '{key}' does not exist in Redis."
        )
    
    redis_cli.set(key, value)
    return {"message": f"Key '{key}' successfully updated."}


@app.delete("/redis/{key}")
async def delete_redis_key(
    key: str, curr_user: User = Depends(get_current_user_authorization_on_redis)
):
    """
    This function deletes an existing Redis key. If the key does not exist, an error is raised.

    Params:
    - key (str): The Redis key to be deleted.
    - curr_user (User): The authorized user retrieved via OAuth2.

    Returns:
    - dict: A success message confirming key deletion.

    Raises:
    - HTTPException: If the key does not exist, a 404 Not Found error is raised.
    """
    if not redis_cli.exists(key):
        raise HTTPException(
            status_code=404, detail=f"Key '{key}' does not exist in Redis."
        )
    
    redis_cli.delete(key)
    return {"message": f"Key '{key}' successfully deleted."}

