from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *


router = APIRouter(tags=["Schemas"])

@router.get("/workspace-service/v1/schema/list-filter")
async def list_schema_in_catalog(
    req: Request,
    workspaceId: str,
    catalogId: str,
    curr_user: str = Depends(get_current_active_user)
):
    await check_catalog_authorization(req, curr_user, workspaceId, catalogId)
    logger.info(f"Catalog {catalogId} access granted! List schemas")
    return {"message": f"Catalog {catalogId} access granted! List schemas"}


@router.post("/workspace-service/v1/schema/create-new")
async def create_new_schema(
    req: Request,
    request_body: CreateSchemaRequest,
    curr_user: User = Depends(get_current_active_user)
):
    workspaceId = request_body.workspaceId
    catalogId = request_body.catalogId
    await check_catalog_authorization(req, curr_user, workspaceId, catalogId)
    
    schemaId = request_body.name
    isPrivate = request_body.isPrivate
    logger.info(f"Schema {schemaId} is being created!")
    
    casbin_enforcer.add_policy(
        AccessLevel.SCHEMA_OWNER.value, curr_user.username, f"{workspaceId}.{catalogId}.{schemaId}{optional_trailing_dot}", 
        ".*", f'.*', "allow"
    )
    
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.SCHEMA_DENY_ALL.value, f".*", f"{workspaceId}.{catalogId}.{schemaId}{optional_trailing_dot}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {"message": f"Schema {schemaId} created!"}

@router.get("/workspace-service/v1/schema/detail")
async def read_schema(
    req: Request,
    workspaceId: str,
    catalogId: str,
    schemaId: str,
    curr_user: str = Depends(get_current_active_user)
):
    await check_schema_authorization(req, curr_user, workspaceId, catalogId, schemaId)
    logger.info(f"Schema {schemaId} access granted! Read details")
    return {"message": f"Schema {schemaId} access granted! Read details"}