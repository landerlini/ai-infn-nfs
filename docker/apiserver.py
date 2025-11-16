import os
import zlib
from fastapi.responses import JSONResponse

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import logging
import subprocess
from typing import List, Tuple
from dataclasses import dataclass

@dataclass(frozen=True)
class Group:
    gid: int
    name: str
    path: str


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

def hash_user(name: str) -> int:
    return zlib.crc32(name.encode('ascii')) % 200000 + 50000

def hash_group(name: str) -> int:
    return zlib.crc32(name.encode('ascii')) % 49000 + 1000

def maybe_create_user(
        username: str,
        groupname: str,
        uid: int,
        gid: int,
        homedir: str,
        groups: List[Group] = None,
):
    subprocess.run(["addgroup", f"-g{gid}", groupname])
    subprocess.run(["mkdir", "-p", homedir])
    subprocess.run(["chown", "-R", f"{uid}:{gid}", homedir])

    adduser_cmd = ["adduser", "-D", f"-u{uid}", "-s/sbin/nologin", f"-G{username}", f"-h{homedir}", username]
    logging.info(' '.join(adduser_cmd))

    adduser = subprocess.run(adduser_cmd)
    if adduser.returncode:
        raise HTTPException(500, f"Failed ensuring user {username}")

    if groups is not None:
        for group in groups:
            subprocess.run(["addgroup", f"-g{group.id}", group.name])
            subprocess.run(["mkdir", "-p", homedir])
            subprocess.run(["chown", "-R", f"root:{group.name}", group.path])
            subprocess.run(["adduser", username, group.name])

@app.get("/uid", response_class=JSONResponse)
def uid(username: str):
    ## Here one should implement lookup to avoid collisions
    return JSONResponse(status_code=200, contents=dict(value=hash_user(username)))

@app.get("/gid", response_class=JSONResponse)
def uid(groupname: str):
    ## Here one should implement lookup to avoid collisions
    return JSONResponse(status_code=200, contents=dict(value=hash_group(groupname)))

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
async def ensure_user(name: str, groups: Optional[str] = None, _: str = Depends(authadmin)):
    groups = [g for g in groups.split(' ') if g not in ['', ' ']]
    uid = str(hash_user(name))
    gid = str(hash_user(name))
    homedir=os.path.join(BASEDIR, f"user-{name}")

    logging.info(f"Ensure existence of user {name}:{gid} ({', '.join(groups)})")

    maybe_create_user(
        username=name,
        groupname=name,
        uid=uid,
        gid=gid,
        homedir=homedir,
        groups=[Group(gid=hash_group(g), name=g, path=os.path.join(BASEDIR, f'shared-{g}')) for g in groups],
    )

    return JSONResponse(
        status_code=200,
        content=dict(
            message=f'User {name} ({uid}:{gid}) created',
            username=name,
            groupname=name,
            uid=uid,
            gid=gid,
            homedir=homedir,
            groups=groups,
        ))

################################################################################
import os
for values in [line.split(':') for line in os.environ.get("CLUSTER_SERVICES", "").split("\n")]:
    if len(values) != 4:
        logging.warning(f"Ignoring CLUSTER_SERVICE: {values}")
        continue

    uid, gid, name, path = values

    maybe_create_user(
        username=name,
        groupname=name,
        uid=uid,
        gid=gid,
        homedir=os.path.join(BASEDIR, path),
    )
