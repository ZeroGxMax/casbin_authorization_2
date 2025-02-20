# from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.responses import RedirectResponse
from settings import MODEL_CONF_PATH, POLICY_CSV_PATH
import casbin
from utils import User, UsersDAO, DeleteJobRequest, CreateTaskRequest, CreateCatalogRequest
from utils import *
from loguru import logger
import json
from constants import AccessLevel
from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi import Request, HTTPException, status
import json
from utils import extract_request_body
import casbin_pymongo_adapter

users_dao = UsersDAO()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

casbin_enforcer = casbin.Enforcer(MODEL_CONF_PATH, POLICY_CSV_PATH, True)

async def check_organization_authorization(req: Request, curr_user, organizationId: str):
    sub = curr_user.username  # The user ID
    obj = organizationId  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)
    
async def check_bucket_authorization(req: Request, curr_user, organizationId: str, bucketId: str):
    sub = curr_user.username  # The user ID
    obj = f"{organizationId}:{bucketId}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)
    
async def check_folder_authorization(req: Request, curr_user, organizationId: str, folder: str):
    sub = curr_user.username  # The user ID
    obj = f"{organizationId}:{folder}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)

async def check_workspace_authorization(req: Request, curr_user, workspaceId: str):
    """
    Checks if the user has authorization to access a specific workspace.

    Args:
        req (Request): The FastAPI request object.
        curr_user (User): The authenticated user.
        workspaceId (str): The workspace being accessed.

    Raises:
        HTTPException: If the user is not authorized.

    Returns:
        None (continues execution if authorized).
    """
    sub = curr_user.username  # The user ID
    obj = workspaceId  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)

async def check_job_authorization(req: Request, curr_user, workspaceId: str, jobId: str):
    """
    Verifies whether the user is authorized to access a specific job within a workspace.

    Args:
        req (Request): The FastAPI request object containing request details.
        curr_user (User): The authenticated user attempting to access the job.
        workspaceId (str): The workspace in which the job is located.
        jobId (str): The specific job the user is trying to access.

    Raises:
        HTTPException: If the user does not have the necessary permissions.

    Returns:
        None: Proceeds with execution if authorization is granted.
    """
    sub = curr_user.username  # The user ID
    obj = f"{workspaceId}.{jobId}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)
    
async def check_catalog_authorization(req: Request, curr_user, workspaceId: str, catalogId: str):
    sub = curr_user.username  # The user ID
    obj = f"{workspaceId}.{catalogId}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)
    
async def check_schema_authorization(req: Request, curr_user, workspaceId: str, catalogId: str, schemaId: str):
    sub = curr_user.username  # The user ID
    obj = f"{workspaceId}.{catalogId}.{schemaId}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)
    
async def check_table_authorization(req: Request, curr_user, workspaceId: str, 
                                    catalogId: str, schemaId: str, tableId: str):
    sub = curr_user.username  # The user ID
    obj = f"{workspaceId}.{catalogId}.{schemaId}.{tableId}"  # The workspace being accessed
    act = req.method  # The action (GET, POST, etc.)
    
    req_body = await extract_request_body(req)  # Extract request body as JSON string
    
    casbin_authorize(sub, obj, act, req_body)


def casbin_authorize(sub: str, obj: str, act: str, req_body: str):
    """Casbin Authorization Middleware"""
    eft = casbin_enforcer.enforce(sub, obj, act, req_body)
    if not eft:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Method not authorized for this user",
        )

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


# async def get_current_user_authorization(
#     req: Request, curr_user: User = Depends(get_current_active_user)
# ):
#     """
#     Verifies that the current user has the necessary authorization to access an API.

#     Params:
#     - req (Request): The incoming request object that contains the URL and HTTP method.
#     - curr_user (User): The currently authenticated user, retrieved via OAuth2 token and
#     validated for activity.

#     Returns:
#     - User: The authenticated user if authorization is granted.

#     Raises:
#     - HTTPException: If the user is not authorized to perform the requested action, a 401
#     Unauthorized error is raised.
#     """
#     sub = curr_user.username
#     obj = f"{req.url.path}?{req.url.query}" if req.url.query else req.url.path
#     act = req.method
    
#     logger.info(f"obj: {obj}")
#     try:
#         req_body = await req.json()
#         req_body = json.dumps(req_body)
#     except Exception:
#         req_body = ""
#     logger.warning(f"req_body: {req_body}")
#     casbin_authorize(sub, obj, act, req_body)
#     return curr_user