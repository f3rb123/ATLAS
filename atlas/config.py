from pathlib import Path
from functools import lru_cache
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator, Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ATLAS_", env_file=None, extra="ignore"
    )
    env: str = "development"
    database_url: str = Field(default="sqlite:///.runtime/atlas.db", repr=False)
    database_url_file_password: str | None = None
    redis_password_file: str | None = None
    redis_url: str = "redis://localhost:6379/0"
    external_url: str = "http://localhost:8000"
    master_key_file: str = ".runtime/master.key"
    data_dir: str = ".runtime"
    gateway_url: str | None = None
    relay_url: str | None = None
    service_token_file: str | None = None
    research_token_file: str | None = None
    verify_token_file: str | None = None
    api_token_file: str | None = None
    provider_key_file: str | None = Field(default=None, repr=False)
    global_token_cap: int = Field(default=50000000, ge=1, le=50000000)
    token_allocation: int = Field(default=2000000, ge=1, le=50000000)
    validation_token_reserve: int = Field(default=200000, ge=0, le=50000000)
    passkey_only_recovery: bool = False
    require_mfa: bool = False
    worker_concurrency: int = Field(default=8, ge=1, le=16)
    gateway_timeout_seconds: int = Field(default=45, ge=30, le=180)
    max_provider_concurrency: int = Field(default=8, ge=1, le=32)
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_cache_dir: str | None = None
    monthly_budget: float = 100
    max_concurrent_http: int = Field(default=8, ge=1, le=32)
    max_request_bytes: int = Field(
        default=21 * 1024 * 1024, ge=1024, le=21 * 1024 * 1024
    )
    max_queued_runs: int = Field(default=100, ge=1, le=1000)
    max_campaign_runs: int = Field(default=3, ge=1, le=100)
    provider_plugins: list[str] = []
    provider_allowlist: list[str] = []
    provider_local_allowlist: list[str] = []

    @model_validator(mode="after")
    def resolve_secret_selectors(self):
        from urllib.parse import quote, urlsplit, urlunsplit

        origin = urlsplit(self.external_url)
        if (
            not origin.hostname
            or origin.username
            or origin.password
            or origin.query
            or origin.fragment
            or origin.path not in ("", "/")
            or origin.scheme not in ("http", "https")
        ):
            raise ValueError(
                "External URL must be an explicit origin without credentials/path/query"
            )
        hostname = origin.hostname.encode("idna").decode("ascii")
        port = origin.port
        netloc = ("[" + hostname + "]") if ":" in hostname else hostname
        if port and port != (443 if origin.scheme == "https" else 80):
            netloc += ":" + str(port)
        self.external_url = urlunsplit((origin.scheme, netloc, "", "", ""))
        if self.database_url_file_password and "{password}" in self.database_url:
            self.database_url = self.database_url.replace(
                "{password}",
                quote(
                    Path(self.database_url_file_password).read_text().strip(), safe=""
                ),
            )
        if self.redis_password_file and "@" not in self.redis_url:
            self.redis_url = self.redis_url.replace(
                "redis://",
                "redis://:"
                + quote(Path(self.redis_password_file).read_text().strip(), safe="")
                + "@",
            )
        return self

    @property
    def production(self):
        return self.env == "production"


@lru_cache
def settings():
    # A raw credential may legitimately be named .env. Never parse it as config.
    # Dotenv configuration is opt-in through an explicit, non-secret selector.
    return Settings(_env_file=os.environ.get("ATLAS_CONFIG_FILE"))
