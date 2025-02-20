from fastapi import APIRouter, Depends, Request
from loguru import logger
from utils import *
from services.auth_service import *
from constants import *

router = APIRouter(tags=["Jobs"])

@router.get("/workflow-service/v1/job/list-filter")
async def list_all_job(
    req: Request,
    workspaceId: str,
    curr_user: User = Depends(get_current_active_user)
):
    """
    Mock API for "/job" path. 
    
    This endpoint is used to check authorization. All users may access this API
    
    Args:
    curr_user (User, optional): The authenticated user making the request. 
        Defaults to Depends(get_current_active_user).

    Returns:
        dict: A message confirming the retrieval of all jobs. (mock)
    """
    await check_workspace_authorization(req, curr_user, workspaceId)
    
    logger.info(f"List all job in workspace {workspaceId}")
    return {"message": f"List all job in workspace {workspaceId}"}
    
@router.get("/workflow-service/v1/job/detail")
async def read_job(
    req: Request,
    workspaceId: str,
    jobId: str,
    curr_user: User = Depends(get_current_active_user),
):
    await check_job_authorization(req, curr_user, workspaceId, jobId)
    
    logger.info(f"Job {jobId} access granted")
    return {f"Job {jobId} access granted"}
    
@router.post("/workflow-service/v1/job/delete")
async def delete_job(
    req: Request,
    request_body: DeleteJobRequest,
    curr_user: User = Depends(get_current_active_user)
):
    """
    Mock API for deleting a job.

    Returns:
        dict: A message confirming the deletion of the specified job.
    """
    jobId = request_body.jobId
    workspaceId = request_body.workspaceId
    
    await check_job_authorization(req, curr_user, workspaceId, jobId)
    logger.warning(f"Job {request_body.jobId} deleted!")
    return {f"Job {request_body.jobId} deleted!"}

@router.post("/workflow-service/v1/job/create-new")
async def create_new_job(
    req: Request,
    request_body: CreateJobRequest,
    curr_user: User = Depends(get_current_active_user)
):
    workspaceId = request_body.workspaceId
    await check_workspace_authorization(req, curr_user, workspaceId)
    jobId = request_body.name
    isPrivate = request_body.isPrivate
    
    logger.info(f"Job {jobId} is being created!")
    
    # Add all permission to owner
    casbin_enforcer.add_policy(
        AccessLevel.JOB_OWNER.value, curr_user.username, f"{workspaceId}.{jobId}{optional_trailing_dot}", 
        ".*", f'.*', "allow"
    )
    
    # If the job is private, deny other people
    # Add all permission to owner
    if isPrivate:
        casbin_enforcer.add_policy(
            AccessLevel.JOB_DENY_ALL.value, f".*", f"{workspaceId}.{jobId}{optional_trailing_dot}", 
            ".*", f'.*', "deny"
        )
    
    casbin_enforcer.save_policy()
    
    return {f"Job {jobId} created!"}