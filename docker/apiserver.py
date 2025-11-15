import os
from fastapi.responses import JSONResponse

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import logging
import subprocess


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

app = FastAPI()
security = HTTPBasic()

USERNAME = os.environ.get("HTTP_USERNAME")
PASSWORD = os.environ.get("HTTP_PASSWORD")
BASEDIR = os.environ.get("BASEDIR", "/exports")

if not USERNAME:
    raise ValueError("Invalid HTTP_USERNAME for administration tasks")

if not PASSWORD:
    raise ValueError("Invalid HTTP_PASSWORD for administration tasks")


def authadmin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
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
async def root(user: str = Depends(authadmin)):
    return {"message": f"Hello, {user}!"}

@app.get("/ensure-user", response_class=JSONResponse)
async def ensure_user(uid: int, gid: int, name: str, groups: str, _: str = Depends(authadmin)):
    groups = groups.split(' ')
    logging.info(f"Ensure existence of user {name}:{gid} ({', '.join(groups)})")

    for group in groups:
        subprocess.run([
            "groupadd", "-f", group
        ])

        subprocess.run([
            "mkdir", "-p", os.path.join(BASEDIR, f"shared-{group}"),
        ])

        subprocess.run([
            "chown", "-R", f"root:{group}", os.path.join(BASEDIR, f"shared-{group}"),
        ])

    subprocess.run([
        "useradd",
        f"-f",
        f"-u{uid}",
        f"-g{gid}",
        f"-s/sbin/nologin",
        f"-G{','.join(groups)}"
    ])

    subprocess.run([
        "mkdir", "-p", os.path.join(BASEDIR, f"user-{name}")
    ])

    subprocess.run([
        "chown", "-R", f"{uid}:{gid}", os.path.join(BASEDIR, f"user-{name}")
    ])

    return JSONResponse(status_code=200, content=dict(message=f'User {name} ({uid}:{gid}) created'))

