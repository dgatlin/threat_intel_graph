"""Threat Actor data models."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatActorMotivation(str, Enum):
    """Threat actor motivations."""
    ESPIONAGE = "espionage"
    FINANCIAL = "financial"
    HACKTIVISM = "hacktivism"
    TERRORISM = "terrorism"
    WARFARE = "warfare"
    CRIMINAL = "criminal"
    UNKNOWN = "unknown"


class ThreatActorStatus(str, Enum):
    """Threat actor status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISRUPTED = "disrupted"
    UNKNOWN = "unknown"


class ThreatActor(BaseModel):
    """Threat Actor model."""
    
    id: str = Field(..., description="Unique threat actor identifier")
    name: str = Field(..., description="Threat actor name")
    aliases: List[str] = Field(default=[], description="Alternative names")
    
    # Attribution
    country: Optional[str] = Field(None, description="Country of origin")
    motivation: ThreatActorMotivation = Field(ThreatActorMotivation.UNKNOWN, description="Primary motivation")
    status: ThreatActorStatus = Field(ThreatActorStatus.ACTIVE, description="Current status")
    sophistication: str = Field("unknown", description="Technical sophistication level")
    
    # Capabilities
    ttps: List[str] = Field(default=[], description="Tactics, Techniques, Procedures")
    tools: List[str] = Field(default=[], description="Known tools and malware")
    targets: List[str] = Field(default=[], description="Target industries/organizations")
    
    # Relationships
    campaigns: List[str] = Field(default=[], description="Associated campaigns")
    iocs: List[str] = Field(default=[], description="Associated IOCs")
    malwares: List[str] = Field(default=[], description="Associated malware")
    
    # Metadata
    first_seen: Optional[datetime] = Field(None, description="First observation")
    last_seen: Optional[datetime] = Field(None, description="Last observation")
    source: str = Field(..., description="Data source")
    description: Optional[str] = Field(None, description="Threat actor description")
    
    # Additional context
    context: Dict[str, Any] = Field(default={}, description="Additional context data")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ThreatActorSearchRequest(BaseModel):
    """Request model for threat actor search."""
    
    name: Optional[str] = Field(None, description="Search by name or alias")
    country: Optional[str] = Field(None, description="Filter by country")
    motivation: Optional[ThreatActorMotivation] = Field(None, description="Filter by motivation")
    status: Optional[ThreatActorStatus] = Field(None, description="Filter by status")
    campaign: Optional[str] = Field(None, description="Filter by associated campaign")
    limit: int = Field(100, ge=1, le=1000, description="Maximum results")
    offset: int = Field(0, ge=0, description="Result offset")


class ThreatActorSearchResponse(BaseModel):
    """Response model for threat actor search."""
    
    threat_actors: List[ThreatActor] = Field(..., description="Matching threat actors")
    total_count: int = Field(..., description="Total number of matching threat actors")
    search_params: ThreatActorSearchRequest = Field(..., description="Search parameters used")
    search_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Search timestamp")


class ThreatAttribution(BaseModel):
    """Threat attribution result."""
    
    campaign_id: str = Field(..., description="Campaign identifier")
    attributed_actors: List[Dict[str, Any]] = Field(..., description="Attributed threat actors with confidence scores")
    attribution_confidence: float = Field(..., ge=0.0, le=1.0, description="Overall attribution confidence")
    attribution_method: str = Field(..., description="Method used for attribution")
    attribution_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Attribution timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }