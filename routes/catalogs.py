from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *


router = APIRouter(tags=["Catalog"])


@router.get("/workspace-service/v1/catalog/list-filter")
async def list_all_catalog(
    req: Request,
    workspaceId: str,
    curr_user: User = Depends(get_current_active_user)
):
    """
    Mock API for "/catalog". 
    
    Args:
    curr_user (User, optional): The authenticated user making the request. 
        Defaults to Depends(get_current_active_user).

    Returns:
        dict: A message confirming the retrieval of all jobs. (mock)
    """
    await check_workspace_authorization(req, curr_user, workspaceId)
    logger.info(f"List all catalog in workspace {workspaceId}")
    return {"message": f"List all catalog in workspace {workspaceId}"}

@router.post("/workspace-service/v1/catalog/create-new")
async def create_new_catalog(
    req: Request,
    request_body: CreateCatalogRequest,
    curr_user: User = Depends(get_current_active_user)
):
    workspaceId = request_body.workspaceId
    await check_workspace_authorization(req, curr_user, workspaceId)
    
    catalogId = request_body.name
    isPrivate = request_body.isPrivate
    
    logger.info(f"Catalog {catalogId} is being created!")
    
    casbin_enforcer.add_policy(
        AccessLevel.CATALOG_OWNER.value, curr_user.username, f"{workspaceId}.{catalogId}{optional_trailing_dot}", 
        ".*", f'.*', "allow"
    )
    
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.CATALOG_DENY_ALL.value, f".*", f"{workspaceId}.{catalogId}{optional_trailing_dot}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {f"Catalog {catalogId} created!"}
    
@router.get("/workspace-service/v1/catalog/detail")
async def read_catalog(
    req: Request,
    catalogId: str,
    workspaceId: str = "default",
    curr_user: str = Depends(get_current_active_user)
):
    await check_catalog_authorization(req, curr_user, workspaceId, catalogId)
    logger.info(f"Catalog {catalogId} access granted! Read details")
    return {"message": f"Catalog {catalogId} access granted! Read details"}