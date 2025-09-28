"""Campaign data models."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class CampaignStatus(str, Enum):
    """Campaign status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPLETED = "completed"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class Campaign(BaseModel):
    """Campaign model."""
    
    id: str = Field(..., description="Unique campaign identifier")
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    
    # Timeline
    start_date: Optional[datetime] = Field(None, description="Campaign start date")
    end_date: Optional[datetime] = Field(None, description="Campaign end date")
    status: CampaignStatus = Field(CampaignStatus.UNKNOWN, description="Campaign status")
    
    # Objectives and targets
    objectives: List[str] = Field(default=[], description="Campaign objectives")
    target_industries: List[str] = Field(default=[], description="Target industries")
    target_countries: List[str] = Field(default=[], description="Target countries")
    target_organizations: List[str] = Field(default=[], description="Target organizations")
    
    # Associated entities
    threat_actors: List[str] = Field(default=[], description="Associated threat actors")
    iocs: List[str] = Field(default=[], description="Associated IOCs")
    ttps: List[str] = Field(default=[], description="Associated TTPs")
    malwares: List[str] = Field(default=[], description="Associated malware")
    
    # Metadata
    source: str = Field(..., description="Data source")
    tags: List[str] = Field(default=[], description="Campaign tags")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Campaign confidence score")
    
    # Additional context
    context: Dict[str, Any] = Field(default={}, description="Additional context data")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class CampaignSearchRequest(BaseModel):
    """Request model for campaign search."""
    
    name: Optional[str] = Field(None, description="Search by campaign name")
    status: Optional[CampaignStatus] = Field(None, description="Filter by status")
    threat_actor: Optional[str] = Field(None, description="Filter by threat actor")
    target_industry: Optional[str] = Field(None, description="Filter by target industry")
    start_date_from: Optional[datetime] = Field(None, description="Filter by start date from")
    start_date_to: Optional[datetime] = Field(None, description="Filter by start date to")
    limit: int = Field(100, ge=1, le=1000, description="Maximum results")
    offset: int = Field(0, ge=0, description="Result offset")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class CampaignSearchResponse(BaseModel):
    """Response model for campaign search."""
    
    campaigns: List[Campaign] = Field(..., description="Matching campaigns")
    total_count: int = Field(..., description="Total number of matching campaigns")
    search_params: CampaignSearchRequest = Field(..., description="Search parameters used")
    search_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Search timestamp")


class CampaignTimeline(BaseModel):
    """Campaign timeline analysis."""
    
    campaign_id: str = Field(..., description="Campaign identifier")
    timeline_events: List[Dict[str, Any]] = Field(..., description="Timeline events")
    key_milestones: List[Dict[str, Any]] = Field(..., description="Key campaign milestones")
    ioc_timeline: List[Dict[str, Any]] = Field(..., description="IOC appearance timeline")
    ttp_evolution: List[Dict[str, Any]] = Field(..., description="TTP evolution over time")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }