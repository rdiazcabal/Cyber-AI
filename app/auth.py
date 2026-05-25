from app import database
import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User, Company

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_COMPANY = os.getenv("ADMIN_COMPANY", "Cyber-AI Internal")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is required")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()

    if not user or not user.is_active:
        return False

    if not verify_password(password, user.password_hash):
        return False

    return user

def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User is inactive or not found")
            return user
        finally:
            db.close()

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_super_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin role required")
    return current_user

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["super_admin", "company_admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user

def bootstrap_admin_user():
    if not ADMIN_USER or not ADMIN_PASSWORD:
        print("Bootstrap admin skipped: ADMIN_USER or ADMIN_PASSWORD not configured")
        return

    db = SessionLocal()
    try:
        company = db.query(Company).filter(Company.name == ADMIN_COMPANY).first()

        if not company:
            company = Company(
                name=ADMIN_COMPANY,
                is_active=True,
                plan="enterprise",
                subscription_status="active",
                max_users=999999,
                max_integrations=999999,
                license_required=False,
            )
            db.add(company)
            db.commit()
            db.refresh(company)

        user = db.query(User).filter(User.username == ADMIN_USER).first()

        if not user:
            db.add(
                User(
                    username=ADMIN_USER,
                    password_hash=hash_password(ADMIN_PASSWORD),
                    full_name="Master Admin",
                    role="super_admin",
                    company_id=company.id,
                    is_active=True,
                )
            )
            db.commit()
            return

        has_changes = False

        if user.company_id is None:
            user.company_id = company.id
            has_changes = True

        if user.role != "super_admin":
            user.role = "super_admin"
            has_changes = True

        if not user.is_active:
            user.is_active = True
            has_changes = True

        # Do not overwrite admin password on every container restart.
        # Password changes must be managed from the application UI.
        force_admin_password_reset = os.getenv(
            "BOOTSTRAP_ADMIN_FORCE_PASSWORD_RESET",
            "false"
        ).lower() == "true"

        if force_admin_password_reset and not verify_password(ADMIN_PASSWORD, user.password_hash):
            user.password_hash = hash_password(ADMIN_PASSWORD)
            has_changes = True

        if has_changes:
            db.commit()

    finally:
        db.close()

def is_super_admin(user: User) -> bool:
    return user.role == "super_admin"

def is_company_admin(user: User) -> bool:
    return user.role == "company_admin"

def require_super_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin role required")
    return current_user

def require_admin_scope(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["super_admin", "company_admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user