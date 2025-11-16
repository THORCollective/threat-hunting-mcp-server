from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # MCP Server
    server_name: str = "threat_hunting_kb"

    # Atlassian (optional - commented out for now)
    atlassian_url: Optional[str] = None
    atlassian_username: Optional[str] = None
    atlassian_api_token: Optional[str] = None
    confluence_space: str = "THREATHUNT"
    jira_project: str = "HUNT"

    # Splunk (optional - commented out for now)
    splunk_host: Optional[str] = None
    splunk_port: int = 8089
    splunk_token: Optional[str] = None

    # Security
    jwt_secret: str = "default-secret-change-in-production"
    encryption_key: Optional[str] = None

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    # Logging
    log_level: str = "INFO"
    audit_log_path: str = "/tmp/threat_hunting_mcp_audit.log"

    # ML/NLP
    spacy_model: str = "en_core_web_lg"

    # HEARTH Community Integration
    hearth_path: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Ignore extra fields in .env


settings = Settings()
