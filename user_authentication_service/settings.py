"""Central settings for the authentication service."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Load database and token settings from the environment."""

    database_url: str = "sqlite:///./auth.db"
    secret_key: str = "change-me-in-production"
    access_token_expire_seconds: int = 3600

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings() -> Settings:
    """Return a cached application settings instance."""
    return Settings()
