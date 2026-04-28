import os
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CyberAI123!")

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


def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


def bootstrap_admin_user():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == ADMIN_USER).first()
        if not user:
            db.add(
                User(
                    username=ADMIN_USER,
                    password_hash=hash_password(ADMIN_PASSWORD),
                    full_name="Container Admin",
                    is_admin=True,
                    is_active=True,
                )
            )
            db.commit()
    finally:
        db.close()
