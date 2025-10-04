"""Configuration settings for Threat Intelligence Graph API."""

from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings."""
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_title: str = "Threat Intelligence Graph API"
    api_version: str = "1.0.0"
    debug: bool = False
    
    # Neo4j Configuration
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "threat_intel_password"
    neo4j_database: str = "neo4j"
    
    # External Threat Feeds
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    threat_feeds_api_key: Optional[str] = None
    
    # Security
    secret_key: str = "your-secret-key-change-in-production"
    access_token_expire_minutes: int = 30
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    # Kafka Configuration
    kafka_brokers: str = "localhost:9092"
    kafka_topic_threat_intel: str = "threat_intelligence"
    kafka_topic_ioc_correlation: str = "ioc_correlation"
    
    # Redis Configuration
    redis_url: str = "redis://localhost:6379"
    redis_db: int = 0
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()