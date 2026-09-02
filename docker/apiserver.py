import os
from urllib.request import Request
import zlib
from fastapi.responses import JSONResponse, FileResponse
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import logging
import subprocess
from typing import List, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


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

# Avoid logging health check
class HealthFilter(logging.Filter):
    def filter(self, record):
        return "/health" not in record.getMessage()

logging.getLogger("uvicorn.access").addFilter(HealthFilter())


app = FastAPI()
security = HTTPBasic()

USERNAME = os.environ.get("HTTP_USERNAME")
PASSWORD = os.environ.get("HTTP_PASSWORD")
BASEDIR = os.environ.get("BASEDIR", "/exports")
DBFILE = os.environ.get("DBFILE", os.path.join(BASEDIR, 'hashes.sqlite'))
DBAUTH = os.environ.get("DBAUTH", os.path.join("/run", "aiinfn", "dbauth"))
EXPIRATION_DAYS = int(os.environ.get("EXPIRATION_DAYS", "30"))

if not USERNAME:
    raise ValueError("Invalid HTTP_USERNAME for administration tasks")

if not PASSWORD:
    raise ValueError("Invalid HTTP_PASSWORD for administration tasks")

def handle_collision(name: str, computed_hash: int, max_recursion_depth: int = 100) -> int:
    if max_recursion_depth == 0:
        raise HTTPException(500, f"Too many resources with names colliding with: {name}")

    with sqlite3.connect(DBFILE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS hashes (hash INTEGER PRIMARY KEY, name TEXT);")

        # Case 1. User exists and it is registered with its own hash. Most frequent case, treated separately.
        names = db.execute("SELECT name FROM hashes WHERE hash = ?;", (computed_hash,)).fetchall()
        if len(names) == 1 and names[0][0] == name:
            logging.info(f"Collision check: {name} was known with id {computed_hash}")
            return computed_hash

        # Case 2. User exists but it's registered with a different hash
        hashes = db.execute("SELECT hash FROM hashes WHERE name = ?;", (name,)).fetchall()
        if len(hashes) == 1:
            logging.info(f"Collision check: {name} was known with id {hashes[0][0]} to prevent collision with {names}")
            return hashes[0][0]

        # Case 3. User is not registered and no other user has the same hash.
        while max_recursion_depth:
            try:
                db.execute("INSERT INTO hashes (hash, name) VALUES (?, ?);", (computed_hash, name))
                return computed_hash
            except sqlite3.IntegrityError:
                max_recursion_depth -= 1
                computed_hash += 1

        logging.critical(f"Something bad happened with the database")
        raise HTTPException(500, "Failed handling user/group id collision")


def hash_user(name: str) -> int:
    computed_id = zlib.crc32(name.encode('ascii')) % 200000 + 50000
    return handle_collision(name, computed_id)

def hash_group(name: str) -> int:
    computed_id = zlib.crc32(name.encode('ascii')) % 49000 + 1000
    return handle_collision(name, computed_id)

def maybe_create_public(
        path: str,
        mode: "1777",
):
    subprocess.run(["mkdir", "-p", path])
    subprocess.run(["chown", "-R", f"root:anon", path])
    subprocess.run(["chmod", mode, path])

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
    subprocess.run(["chmod", "700", homedir])

    adduser_cmd = ["adduser", "-D", f"-u{uid}", "-s/sbin/nologin", f"-G{username}", f"-h{homedir}", username]
    logging.info(' '.join(adduser_cmd))

    adduser = subprocess.run(adduser_cmd, capture_output=True)
    if adduser.returncode:
        if 'in use' in str(adduser.stderr, 'ascii'):
            logging.warning(f"User '{username}' exists, no check performed on consistency of uid, home and group")
        else:
            logging.critical(f"Failure creating {username}: {adduser.returncode}. \n{adduser.stdout}\n{adduser.stderr}\n")
            raise HTTPException(500, f"Failed ensuring user {username}")

    if groups is not None:
        for group in groups:
            subprocess.run(["addgroup", f"-g{group.gid}", group.name])
            subprocess.run(["mkdir", "-p", group.path])
            subprocess.run(["chown", "-R", f"root:{group.name}", group.path])
            subprocess.run(["chmod", "g+ws", group.path])
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


@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/ensure-user", response_class=JSONResponse)
async def ensure_user(name: str, groups: Optional[str] = None, tenancy: Optional[str] = None, _: str = Depends(authadmin)):
    groups = [g for g in groups.split(' ') if g not in ['', ' ']]
    uid = str(hash_user(name))
    gid = str(hash_user(name))
    basedir = os.path.join(BASEDIR, tenancy) if tenancy else BASEDIR
    homedir = os.path.join(basedir, f"user-{name}")

    logging.info(f"Ensure existence of user {name}:{gid} ({', '.join(groups)})")
    groups = [Group(gid=hash_group(g), name=g, path=os.path.join(basedir, f'shared-{g}')) for g in groups]

    maybe_create_user(
        username=name,
        groupname=name,
        uid=uid,
        gid=gid,
        homedir=homedir,
        groups=groups,
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
            groups=[dict(gid=g.gid, name=g.name) for g in groups],
        ))

def clean_keys(max_keys: int = 10):
    with sqlite3.connect(DBAUTH) as db:
        (n_dropped_keys, n_valid_keys), = db.execute("""
            SELECT 
                COUNT(*) AS n_dropped_keys,
                COUNT(*) FILTER(WHERE expires_at > datetime('now')) AS n_valid_keys
            FROM ssh_keys
            WHERE rowid NOT IN (
                SELECT rowid 
                FROM ssh_keys 
                ORDER BY expires_at DESC 
                LIMIT ?
            );
        """, (max_keys,)).fetchall()

        db.execute("""
            DELETE FROM ssh_keys
            WHERE rowid NOT IN (
                SELECT rowid 
                FROM ssh_keys 
                ORDER BY expires_at DESC 
                LIMIT ?
            );
        """, (max_keys,))

        if n_dropped_keys > 0 and n_valid_keys == 0:
            logging.info(f"Cleaned up {n_dropped_keys} expired SSH keys")
        elif n_dropped_keys > 0 and n_valid_keys > 0:
            logging.warning(f"Cleaned up {n_dropped_keys} expired SSH keys. {n_valid_keys} were still valid.")

@app.get("/keygen", response_class=PlainTextResponse)
def keygen(user: str, expires_in_days: int = 1, _: str = Depends(authadmin)):
    if expires_in_days < 1 or expires_in_days > EXPIRATION_DAYS:
        raise HTTPException(400, f"expires_in_days must be between 1 and {EXPIRATION_DAYS}")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    ssh_public = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    expires_at = (datetime.now() + timedelta(days=expires_in_days)).isoformat()

    with sqlite3.connect(DBAUTH) as db:
        db.execute("""
            INSERT INTO ssh_keys (user, public_key, expires_at) VALUES (?, ?, ?);
        """, (user, ssh_public.decode("utf-8"), expires_at))

    logging.info(f"Generated SSH key for user {user} with expiration: {expires_at}")
    clean_keys(max_keys=10)
    return pem_private.decode("utf-8")

@app.get("/keys/{user}", response_class=PlainTextResponse)
def get_keys(user: str):
    with sqlite3.connect(DBAUTH) as db:
        cursor = db.execute("""
            SELECT public_key 
            FROM ssh_keys 
            WHERE   user = ?
                AND expires_at > datetime('now')
            """, (user,))
        keys = [row[0] for row in cursor.fetchall()]
    return "\n".join(keys)

def localhost_only(request: Request):
    client_ip = request.client.host
    if client_ip not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/passwd", response_class=FileResponse)
def get_passwd(_: None = Depends(localhost_only)):
    return FileResponse("/etc/passwd", media_type="text/plain")

@app.get("/group", response_class=FileResponse)
def get_group(_: None = Depends(localhost_only)):
    return FileResponse("/etc/group", media_type="text/plain")

################################################################################
for values in [line.split(':') for line in os.environ.get("CLUSTER_SERVICES", "").split("\n") if len(line) > 0]:
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

for values in [line.split(':') for line in os.environ.get("ANON_DIRS", "").split("\n") if len(line) > 0]:
    if len(values) != 2:
        logging.warning(f"Ignoring ANON_DIR: {values}")
        continue

    path, mode = values
    if not path.startswith("/"):
        path = os.path.join(BASEDIR, path)

    maybe_create_public(path, mode)

# Ensure the directory for the SSH key database exists
os.makedirs(os.path.dirname(DBAUTH), exist_ok=True)

# Initialize the database for SSH keys if it doesn't exist
with sqlite3.connect(DBAUTH) as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS ssh_keys (
            user TEXT ,
            public_key TEXT,
            expires_at TIMESTAMP DEFAULT (datetime('now', '+1 day'))
            );
    """)
