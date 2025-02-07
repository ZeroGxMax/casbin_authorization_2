# Project Setup & Usage Guide 

## Prerequisite: 
Ensure you have the following installed before running the project: 
- Python (Recommended: 3.10) 
- Redis Server (Running on localhost:6379) 


## Setup Instructions 
### Step 1: Create a Virtual Environment 
```
python3 -m venv venv 
```
### Step 2: Activate the Virtual Environment & Install Dependencies 
```
source venv/bin/activate 
pip install -r requirements.txt 
```
### Step 3: Start the FastAPI Server 
```
sh start.sh 
```


## How to Use 
# Step 1: 
- Go to: http://localhost:8000 
# Step 2: Log in 
Use the credentials found in utils.py. For example: 
- Username: employee 
- Password: secret3 

# Step 3: Explore the APIs
- Refer to policy.csv for correct policy-based access control. 
- Test API endpoints via the FastAPI interactive docs at: http://localhost:8000/docs 


