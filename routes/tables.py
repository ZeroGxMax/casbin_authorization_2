from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *


router = APIRouter(tags=["Tables"])

@router.get("/workspace-service/v1/table/list-filter")
async def list_table_in_schema(
    req: Request,
    workspaceId: str,
    catalogId: str,
    schemaId: str,
    curr_user: str = Depends(get_current_active_user)
):
    await check_schema_authorization(req, curr_user, workspaceId, catalogId, schemaId)
    logger.info(f"Schema {schemaId} access granted! List tables")
    return {"message": f"Schema {schemaId} access granted! List tables"}


@router.post("/workspace-service/v1/table/create-new")
async def create_new_table(
    req: Request,
    request_body: CreateTableRequest,
    curr_user: User = Depends(get_current_active_user)
):
    workspaceId = request_body.workspaceId
    catalogId = request_body.catalogId
    schemaId = request_body.schemaId
    await check_schema_authorization(req, curr_user, workspaceId, catalogId, schemaId)
    isPrivate = request_body.isPrivate
    
    tableId = request_body.name
    logger.info(f"Table {tableId} is being created!")
    
    # Allow all permissions for posting with the table
    casbin_enforcer.add_policy(
        AccessLevel.TABLE_OWNER.value, curr_user.username, f"{workspaceId}.{catalogId}.{schemaId}.{tableId}{optional_trailing_dot}", 
        ".*", f'.*', "allow"
    )
    
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.TABLE_DENY_ALL.value, f".*", f"{workspaceId}.{catalogId}.{schemaId}.{tableId}{optional_trailing_dot}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {"message": f"Table {tableId} created!"}

@router.get("/workspace-service/v1/table/detail")
async def read_table(
    req: Request,
    workspaceId: str,
    catalogId: str,
    schemaId: str,
    tableId: str,
    curr_user: str = Depends(get_current_active_user)
):
    await check_table_authorization(req, curr_user, workspaceId, catalogId, schemaId, tableId)
    logger.info(f"Table {tableId} access granted! Read details")
    return {"message": f"Schema {tableId} access granted! Read details"}

@router.post("/workspace-service/v1/table/load-data")
async def load_data_into_table(
    req: Request,
    request_body: LoadDataRequest,
    curr_user: str = Depends(get_current_active_user)
):
    workspaceId = request_body.workspaceId
    catalogId = request_body.catalogId
    schemaId = request_body.schemaId
    tableId = request_body.tableId
    
    await check_table_authorization(req, curr_user, workspaceId, catalogId, schemaId, tableId)
    
    logger.info(f"Load data in table {tableId}")
    return {"message": f"Load data in table {tableId}"}


@router.get("/workspace-service/v1/table/partition/list")
async def list_partition_in_table(
    req: Request,
    workspaceId: str,
    catalogId: str,
    schemaId: str,
    tableId: str,
    curr_user: str = Depends(get_current_active_user)
):  
    await check_table_authorization(req, curr_user, workspaceId, catalogId, schemaId, tableId)
    
    logger.info(f"Table {tableId} access granted! List tables")
    return {"message": f"Table {tableId} access granted! List table"}