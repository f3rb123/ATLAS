from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator,Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='ATLAS_', env_file='.env', extra='ignore')
    env: str = 'development'
    database_url: str = Field(default='sqlite:///.runtime/atlas.db',repr=False)
    database_url_file_password: str | None = None
    redis_password_file: str | None = None
    redis_url: str = 'redis://localhost:6379/0'
    external_url: str = 'http://localhost:8000'
    master_key_file: str = '.runtime/master.key'
    data_dir: str = '.runtime'
    gateway_url: str | None = None
    relay_url: str | None = None
    service_token_file: str | None = None
    research_token_file: str | None = None
    verify_token_file: str | None = None
    api_token_file: str | None = None
    passkey_only_recovery: bool = False
    monthly_budget: float = 100
    provider_allowlist: list[str] = []
    provider_local_allowlist: list[str] = []
    @model_validator(mode='after')
    def resolve_secret_selectors(self):
        from urllib.parse import quote
        if self.database_url_file_password and '{password}' in self.database_url:
            self.database_url=self.database_url.replace('{password}',quote(Path(self.database_url_file_password).read_text().strip(),safe=''))
        if self.redis_password_file and '@' not in self.redis_url:
            self.redis_url=self.redis_url.replace('redis://','redis://:'+quote(Path(self.redis_password_file).read_text().strip(),safe='')+'@')
        return self
    @property
    def production(self): return self.env == 'production'

@lru_cache
def settings(): return Settings()
