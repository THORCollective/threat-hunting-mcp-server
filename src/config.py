from pydantic_settings import BaseSettings
from typing import Dict, Optional
import os


class Settings(BaseSettings):
    # MCP Server
    server_name: str = "threat_hunting_kb"
    
    # Atlassian
    atlassian_url: str
    atlassian_username: str
    atlassian_api_token: str
    confluence_space: str = "THREATHUNT"
    jira_project: str = "HUNT"
    
    # Splunk
    splunk_host: str
    splunk_port: int = 8089
    splunk_token: str
    
    # Security
    jwt_secret: str
    encryption_key: Optional[str] = None
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    
    # Logging
    log_level: str = "INFO"
    audit_log_path: str = "/var/log/threat_hunting_mcp/audit.log"
    
    # ML/NLP
    spacy_model: str = "en_core_web_lg"

    # HEARTH Community Integration
    hearth_path: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()