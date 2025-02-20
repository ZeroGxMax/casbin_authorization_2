from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *


router = APIRouter(tags=["File"])

@router.get("/storage-service/v1/file/list-filter")
async def list_all_in_folder(
    req: Request,
    organizationId: str,
    folder: str,
    curr_user: User = Depends(get_current_active_user)
):
    await check_folder_authorization(req, curr_user, organizationId, folder)
    logger.info(f"List all file in bucket {folder}")
    return {"message": f"List all file in bucket {folder}"}


@router.post("/storage-service/v1/file/upload")
async def upload_new_file(
    req: Request,
    request_body: UploadFileRequest,
    curr_user: User = Depends(get_current_active_user)
):
    organizationId = request_body.organizationId
    folder = request_body.folder
    await check_bucket_authorization(req, curr_user, organizationId, folder)
    
    fileId = request_body.name
    isPrivate = request_body.isPrivate
    
    logger.info(f"file {fileId} is being created!")
    
    casbin_enforcer.add_policy(
        AccessLevel.FILE_OWNER.value, curr_user.username, f"{organizationId}:{folder}/{fileId}{optional_trailing_forward_slash}", 
        ".*", f'.*', "allow"
    )
    
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.FILE_DENY_ALL.value, f".*", f"{organizationId}:{folder}/{fileId}{optional_trailing_forward_slash}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {f"file {fileId} created!"}
    
@router.post("/storage-service/v1/file/download")
async def read_file(
    req: Request,
    request_body: FileDownloadRequest,
    curr_user: str = Depends(get_current_active_user)
):
    organizationId = request_body.organizationId
    fileId = request_body.fileId
    folder = f"{request_body.folder}/{fileId}"
    await check_folder_authorization(req, curr_user, organizationId, folder)
    logger.info(f"Path{folder} access granted! Read details")
    return {"message": f"Path {folder} access granted! Read details"}