"""IOC (Indicator of Compromise) data models."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    CERTIFICATE = "certificate"


class IOCCategory(str, Enum):
    """Categories of IOCs."""
    MALWARE = "malware"
    ATTACK_INFRASTRUCTURE = "attack_infrastructure"
    COMPROMISED = "compromised"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    C2 = "command_and_control"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


class IOC(BaseModel):
    """Indicator of Compromise model."""
    
    id: str = Field(..., description="Unique IOC identifier")
    type: IOCType = Field(..., description="Type of IOC")
    value: str = Field(..., description="IOC value")
    category: IOCCategory = Field(..., description="IOC category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    
    # Attribution
    threat_actors: List[str] = Field(default=[], description="Associated threat actors")
    campaigns: List[str] = Field(default=[], description="Associated campaigns")
    malwares: List[str] = Field(default=[], description="Associated malware")
    ttps: List[str] = Field(default=[], description="Associated TTPs")
    
    # Metadata
    first_seen: Optional[datetime] = Field(None, description="First observation date")
    last_seen: Optional[datetime] = Field(None, description="Last observation date")
    source: str = Field(..., description="Data source")
    tags: List[str] = Field(default=[], description="IOC tags")
    
    # Correlation
    related_assets: List[str] = Field(default=[], description="Related internal assets")
    related_iocs: List[str] = Field(default=[], description="Related IOCs")
    
    # Additional context
    description: Optional[str] = Field(None, description="IOC description")
    context: Dict[str, Any] = Field(default={}, description="Additional context data")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class IOCSearchRequest(BaseModel):
    """Request model for IOC search."""
    
    asset_id: Optional[str] = Field(None, description="Search IOCs for specific asset")
    ioc_type: Optional[IOCType] = Field(None, description="Filter by IOC type")
    threat_actor: Optional[str] = Field(None, description="Filter by threat actor")
    campaign: Optional[str] = Field(None, description="Filter by campaign")
    confidence_min: Optional[float] = Field(0.0, ge=0.0, le=1.0, description="Minimum confidence")
    limit: int = Field(100, ge=1, le=1000, description="Maximum results")
    offset: int = Field(0, ge=0, description="Result offset")


class IOCSearchResponse(BaseModel):
    """Response model for IOC search."""
    
    iocs: List[IOC] = Field(..., description="Matching IOCs")
    total_count: int = Field(..., description="Total number of matching IOCs")
    search_params: IOCSearchRequest = Field(..., description="Search parameters used")
    search_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Search timestamp")


class AssetThreatContext(BaseModel):
    """Threat intelligence context for an asset."""
    
    asset_id: str = Field(..., description="Asset identifier")
    threat_level: str = Field(..., description="Overall threat level")
    threat_actors: List[str] = Field(default=[], description="Associated threat actors")
    iocs: List[IOC] = Field(default=[], description="Associated IOCs")
    campaigns: List[str] = Field(default=[], description="Associated campaigns")
    ttps: List[str] = Field(default=[], description="Associated TTPs")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence score")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }