from enum import Enum

class AccessLevel(Enum):
    # Organization Level (Level 0)
    ORGANIZATION_OWNER = "20"
    ORGANIZATION_WRITER = "21"
    ORGANIZATION_READER = "22"
    ORGANIZATION_DENY_ALL = "120"
    ORGANIZATION_DENY_WRITE = "121"
    
    # Bucket Level (Level 1)
    BUCKET_OWNER = "30"
    BUCKET_WRITER = "31"
    BUCKET_READER = "32"
    BUCKET_DENY_ALL = "130"
    BUCKET_DENY_WRITE = "131"
    
    # Workspace Level (Level 1)
    WORKSPACE_OWNER = "30"
    WORKSPACE_WRITER = "31"
    WORKSPACE_READER = "32"
    WORKSPACE_DENY_ALL = "130"
    WORKSPACE_DENY_WRITE = "131"
    
    # File Level (Level 2)
    FILE_OWNER = "40"
    FILE_WRITER = "41"
    FILE_READER = "42"
    FILE_DENY_ALL = "140"
    FILE_DENY_WRITE = "141"

    # Catalog Level (Level 2)
    CATALOG_OWNER = "40"
    CATALOG_WRITER = "41"
    CATALOG_READER = "42"
    CATALOG_DENY_ALL = "140"
    CATALOG_DENY_WRITE = "141"
    
    # Job Level (Level 2)
    JOB_OWNER = "40"
    JOB_WRITER = "41"
    JOB_READER = "42"
    JOB_DENY_ALL = "140"
    JOB_DENY_WRITE = "141"

    # Schema Level (Level 3)
    SCHEMA_OWNER = "50"
    SCHEMA_WRITER = "51"
    SCHEMA_READER = "52"
    SCHEMA_DENY_ALL = "150"
    SCHEMA_DENY_WRITE = "151"

    # Table Level (Level 4)
    TABLE_OWNER = "60"
    TABLE_WRITER = "61"
    TABLE_READER = "62"
    TABLE_DENY_ALL = "160"
    TABLE_DENY_WRITE = "161"
    

"""
Example
p, 50, .*, default(\..*)?$, .*, .*, allow
Allows public access to any resource in the "default" workspace if it is open.

p, 30, employee, default.job_1(\..*)?$, .*, .*, allow
Grants full access to job_1 and its sub-resources for the owner.

p, 31, employee, default.job_1(\..*)?$, GET, .*, allow
Allows collaborators to read job_1 and its sub-resources, but not modify them.

p, 42, .*, default.job_1(\..*)?$, .*, .*, deny
Explicitly denies access to job_1 and its sub-resources for staff.
"""
    
optional_trailing_dot = "(\..*)?$"
optional_trailing_colon = "(\:.*)?$"
optional_trailing_forward_slash = "(/.*)?$"
