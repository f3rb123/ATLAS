from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='ATLAS_', env_file='.env', extra='ignore')
    env: str = 'development'
    database_url: str = 'sqlite:///.runtime/atlas.db'
    redis_url: str = 'redis://localhost:6379/0'
    external_url: str = 'http://localhost:8000'
    master_key_file: str = '.runtime/master.key'
    data_dir: str = '.runtime'
    monthly_budget: float = 100
    provider_allowlist: list[str] = []
    provider_local_allowlist: list[str] = []
    @property
    def production(self): return self.env == 'production'

@lru_cache
def settings(): return Settings()
