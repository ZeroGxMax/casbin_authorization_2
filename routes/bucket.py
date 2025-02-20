from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *


router = APIRouter(tags=["Bucket"])

@router.get("/storage-admin-service/v1/bucket/list-filter")
async def list_all_bucket(
    req: Request,
    organizationId: str,
    curr_user: User = Depends(get_current_active_user)
):
    await check_organization_authorization(req, curr_user, organizationId)
    logger.info(f"List all bucket in organization {organizationId}")
    return {"message": f"List all bucket in organization {organizationId}"}


@router.post("/storage-admin-service/v1/bucket/create-new")
async def create_new_bucket(
    req: Request,
    request_body: CreateBucketRequest,
    curr_user: User = Depends(get_current_active_user)
):
    organizationId = request_body.organizationId
    await check_organization_authorization(req, curr_user, organizationId)
    
    bucketId = request_body.name
    isPrivate = request_body.isPrivate
    
    logger.info(f"bucket {bucketId} is being created!")
    
    casbin_enforcer.add_policy(
        AccessLevel.BUCKET_OWNER.value, curr_user.username, f"{organizationId}:{bucketId}{optional_trailing_forward_slash}", 
        ".*", f'.*', "allow"
    )
    
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.BUCKET_DENY_ALL.value, f".*", f"{organizationId}:{bucketId}{optional_trailing_forward_slash}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {f"bucket {bucketId} created!"}
    
@router.get("/storage-admin-service/v1/bucket/detail")
async def read_bucket(
    req: Request,
    bucketId: str,
    organizationId: str,
    curr_user: str = Depends(get_current_active_user)
):
    await check_bucket_authorization(req, curr_user, organizationId, bucketId)
    logger.info(f"bucket {bucketId} access granted! Read details")
    return {"message": f"bucket {bucketId} access granted! Read details"}