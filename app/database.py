import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    DATABASE_FILE = os.getenv("DATABASE_FILE", "./data/cyber_ai.db")
    database_dir = os.path.dirname(DATABASE_FILE)

    if database_dir:
        os.makedirs(database_dir, exist_ok=True)

    DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

engine_args = {}

if DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    **engine_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()