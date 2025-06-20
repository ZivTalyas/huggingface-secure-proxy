from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    app_name: str = "Hugging Face Security Gateway"
    version: str = "1.0.0"
    
    # Security settings
    security_threshold: float = 0.8
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    
    # Model settings
    default_model: str = "distilbert-base-uncased"
    available_models: list = [
        "distilbert-base-uncased",
        "bert-base-uncased",
        "roberta-base"
    ]
    
    # Cache settings
    cache_ttl: int = 3600  # 1 hour
    max_cache_size: int = 1000
    
    # Rate limiting
    max_requests_per_minute: int = 1000
    
    # Database settings
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "security_gateway"
    db_user: str = "admin"
    db_password: str = ""
    
    # Redis settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
