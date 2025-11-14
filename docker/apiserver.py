import os

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()

USERNAME = os.environ.get("HTTP_USERNAME")
PASSWORD = os.environ.get("HTTP_PASSWORD")

if not USERNAME:
    raise ValueError("Invalid HTTP_USERNAME for administration tasks")

if not PASSWORD:
    raise ValueError("Invalid HTTP_PASSWORD for administration tasks")


def authenticated_user(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/")
async def root(user: str = Depends(authenticated_user)):
    return {"message": f"Hello, {user}!"}
