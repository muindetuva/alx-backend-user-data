"""SQLAlchemy database setup and request-scoped session dependency."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from settings import get_settings


settings = get_settings()
connect_args = (
    {"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for persisted SQLAlchemy models."""


def get_db():
    """Yield a database session and always close it afterward."""
    database = SessionLocal()
    try:
        yield database
    finally:
        database.close()
