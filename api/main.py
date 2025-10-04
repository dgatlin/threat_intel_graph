"""Main FastAPI application for Threat Intelligence Graph API."""

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime

from config.settings import settings
from config.logging import configure_logging, get_logger
from api.models.ioc import IOC, IOCSearchRequest, IOCSearchResponse, AssetThreatContext
from api.models.threat_actor import ThreatActor, ThreatActorSearchRequest, ThreatActorSearchResponse
from api.models.campaign import Campaign, CampaignSearchRequest, CampaignSearchResponse
from api.services.ioc_service import IOCService
from api.services.threat_service import ThreatService
from api.services.campaign_service import CampaignService
from database.neo4j.connection import neo4j_connection
from data.ingestion.feed_service import ingest_sample_threat_data

# Configure logging
configure_logging()
logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="Threat intelligence graph for cybersecurity analysis and GNN integration",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency injection
def get_ioc_service() -> IOCService:
    return IOCService()

def get_threat_service() -> ThreatService:
    return ThreatService()

def get_campaign_service() -> CampaignService:
    return CampaignService()


@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info("Starting Threat Intelligence Graph API", version=settings.api_version)


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event."""
    logger.info("Shutting down Threat Intelligence Graph API")
    neo4j_connection.close()


# Health check endpoint
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    neo4j_healthy = neo4j_connection.health_check()
    
    return {
        "status": "healthy" if neo4j_healthy else "unhealthy",
        "service": "threat-intelligence-graph-api",
        "version": settings.api_version,
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "neo4j": "healthy" if neo4j_healthy else "unhealthy"
        }
    }


# IOC endpoints
@app.get("/api/v1/iocs/asset/{asset_id}", response_model=AssetThreatContext)
async def get_asset_threat_context(
    asset_id: str,
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Get threat intelligence context for a specific asset."""
    try:
        context = await ioc_service.get_asset_threat_context(asset_id)
        return context
    except Exception as e:
        logger.error("Failed to get asset threat context", asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")


@app.get("/api/v1/iocs/search", response_model=IOCSearchResponse)
async def search_iocs(
    asset_id: Optional[str] = Query(None, description="Search IOCs for specific asset"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor"),
    campaign: Optional[str] = Query(None, description="Filter by campaign"),
    confidence_min: Optional[float] = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Result offset"),
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Search for IOCs with various filters."""
    try:
        search_params = IOCSearchRequest(
            asset_id=asset_id,
            ioc_type=ioc_type,
            threat_actor=threat_actor,
            campaign=campaign,
            confidence_min=confidence_min,
            limit=limit,
            offset=offset
        )
        
        results = await ioc_service.search_iocs(search_params)
        return results
    except Exception as e:
        logger.error("Failed to search IOCs", error=str(e))
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.post("/api/v1/iocs", response_model=IOC)
async def create_ioc(
    ioc: IOC,
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Create a new IOC."""
    try:
        created_ioc = await ioc_service.create_ioc(ioc)
        return created_ioc
    except Exception as e:
        logger.error("Failed to create IOC", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create IOC: {str(e)}")


@app.post("/api/v1/iocs/{ioc_id}/correlate/{asset_id}")
async def correlate_ioc_with_asset(
    ioc_id: str,
    asset_id: str,
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Correlate an IOC with an asset."""
    try:
        success = await ioc_service.correlate_ioc_with_asset(ioc_id, asset_id)
        if success:
            return {"message": "IOC successfully correlated with asset", "ioc_id": ioc_id, "asset_id": asset_id}
        else:
            raise HTTPException(status_code=400, detail="Failed to correlate IOC with asset")
    except Exception as e:
        logger.error("Failed to correlate IOC with asset", ioc_id=ioc_id, asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")


# Threat Actor endpoints
@app.get("/api/v1/threat-actors/{actor_id}", response_model=ThreatActor)
async def get_threat_actor_info(
    actor_id: str,
    threat_service: ThreatService = Depends(get_threat_service)
):
    """Get detailed threat actor information."""
    try:
        threat_actor = await threat_service.get_threat_actor(actor_id)
        if not threat_actor:
            raise HTTPException(status_code=404, detail=f"Threat actor not found: {actor_id}")
        return threat_actor
    except Exception as e:
        logger.error("Failed to get threat actor", actor_id=actor_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat actor: {str(e)}")


@app.get("/api/v1/threat-actors/search", response_model=ThreatActorSearchResponse)
async def search_threat_actors(
    name: Optional[str] = Query(None, description="Search by name or alias"),
    country: Optional[str] = Query(None, description="Filter by country"),
    motivation: Optional[str] = Query(None, description="Filter by motivation"),
    status: Optional[str] = Query(None, description="Filter by status"),
    campaign: Optional[str] = Query(None, description="Filter by associated campaign"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Result offset"),
    threat_service: ThreatService = Depends(get_threat_service)
):
    """Search for threat actors with various filters."""
    try:
        search_params = ThreatActorSearchRequest(
            name=name,
            country=country,
            motivation=motivation,
            status=status,
            campaign=campaign,
            limit=limit,
            offset=offset
        )
        
        results = await threat_service.search_threat_actors(search_params)
        return results
    except Exception as e:
        logger.error("Failed to search threat actors", error=str(e))
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.post("/api/v1/threat-actors", response_model=ThreatActor)
async def create_threat_actor(
    threat_actor: ThreatActor,
    threat_service: ThreatService = Depends(get_threat_service)
):
    """Create a new threat actor."""
    try:
        created_actor = await threat_service.create_threat_actor(threat_actor)
        return created_actor
    except Exception as e:
        logger.error("Failed to create threat actor", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create threat actor: {str(e)}")


@app.get("/api/v1/threat-actors/{actor_id}/attribution")
async def get_threat_attribution(
    actor_id: str,
    threat_service: ThreatService = Depends(get_threat_service)
):
    """Get threat attribution for a specific actor."""
    try:
        # This would typically get campaigns for the actor and then attribute them
        # For now, return a placeholder response
        return {
            "actor_id": actor_id,
            "attribution_confidence": 0.0,
            "message": "Threat attribution analysis not yet implemented"
        }
    except Exception as e:
        logger.error("Failed to get threat attribution", actor_id=actor_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Attribution failed: {str(e)}")


# Campaign endpoints
@app.get("/api/v1/campaigns/{campaign_id}", response_model=Campaign)
async def get_campaign_info(
    campaign_id: str,
    campaign_service: CampaignService = Depends(get_campaign_service)
):
    """Get detailed campaign information."""
    try:
        campaign = await campaign_service.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail=f"Campaign not found: {campaign_id}")
        return campaign
    except Exception as e:
        logger.error("Failed to get campaign", campaign_id=campaign_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to retrieve campaign: {str(e)}")


@app.get("/api/v1/campaigns/search", response_model=CampaignSearchResponse)
async def search_campaigns(
    name: Optional[str] = Query(None, description="Search by campaign name"),
    status: Optional[str] = Query(None, description="Filter by status"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor"),
    target_industry: Optional[str] = Query(None, description="Filter by target industry"),
    start_date_from: Optional[str] = Query(None, description="Filter by start date from (ISO format)"),
    start_date_to: Optional[str] = Query(None, description="Filter by start date to (ISO format)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Result offset"),
    campaign_service: CampaignService = Depends(get_campaign_service)
):
    """Search for campaigns with various filters."""
    try:
        search_params = CampaignSearchRequest(
            name=name,
            status=status,
            threat_actor=threat_actor,
            target_industry=target_industry,
            start_date_from=start_date_from,
            start_date_to=start_date_to,
            limit=limit,
            offset=offset
        )
        
        results = await campaign_service.search_campaigns(search_params)
        return results
    except Exception as e:
        logger.error("Failed to search campaigns", error=str(e))
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.post("/api/v1/campaigns", response_model=Campaign)
async def create_campaign(
    campaign: Campaign,
    campaign_service: CampaignService = Depends(get_campaign_service)
):
    """Create a new campaign."""
    try:
        created_campaign = await campaign_service.create_campaign(campaign)
        return created_campaign
    except Exception as e:
        logger.error("Failed to create campaign", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create campaign: {str(e)}")


@app.get("/api/v1/campaigns/{campaign_id}/timeline")
async def get_campaign_timeline(
    campaign_id: str,
    campaign_service: CampaignService = Depends(get_campaign_service)
):
    """Get timeline analysis for a threat campaign."""
    try:
        timeline = await campaign_service.analyze_campaign_timeline(campaign_id)
        return timeline
    except Exception as e:
        logger.error("Failed to get campaign timeline", campaign_id=campaign_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Timeline analysis failed: {str(e)}")


@app.get("/api/v1/campaigns/{campaign_id}/attribution")
async def get_campaign_attribution(
    campaign_id: str,
    threat_service: ThreatService = Depends(get_threat_service)
):
    """Get threat attribution for a campaign."""
    try:
        attribution = await threat_service.attribute_threat(campaign_id)
        return attribution
    except Exception as e:
        logger.error("Failed to get campaign attribution", campaign_id=campaign_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Attribution failed: {str(e)}")


# Integration endpoints for GNN project
@app.post("/api/v1/correlate/asset")
async def correlate_asset_with_threats(
    asset_id: str,
    asset_data: dict
):
    """Correlate an internal asset with threat intelligence."""
    # TODO: Implement asset correlation service
    raise HTTPException(status_code=501, detail="Asset correlation service not yet implemented")


@app.get("/api/v1/iocs/{ioc_id}/relationships")
async def get_ioc_relationships(
    ioc_id: str,
    depth: int = Query(2, ge=1, le=5, description="Relationship traversal depth"),
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Get relationship data for graph-based analysis."""
    try:
        relationships = await ioc_service.get_ioc_relationships(ioc_id, depth)
        return {
            "ioc_id": ioc_id,
            "depth": depth,
            "relationships": relationships,
            "count": len(relationships)
        }
    except Exception as e:
        logger.error("Failed to get IOC relationships", ioc_id=ioc_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get relationships: {str(e)}")


@app.get("/api/v1/graph/export")
async def export_graph_data(
    node_types: Optional[str] = Query(None, description="Comma-separated node types to include"),
    relationship_types: Optional[str] = Query(None, description="Comma-separated relationship types to include"),
    ioc_service: IOCService = Depends(get_ioc_service)
):
    """Export graph data for GNN training."""
    try:
        node_types_list = node_types.split(",") if node_types else None
        rel_types_list = relationship_types.split(",") if relationship_types else None
        
        graph_data = await ioc_service.get_graph_export(node_types_list, rel_types_list)
        return graph_data
    except Exception as e:
        logger.error("Failed to export graph data", error=str(e))
        raise HTTPException(status_code=500, detail=f"Graph export failed: {str(e)}")


@app.get("/api/v1/enhance/risk-score")
async def enhance_risk_score(
    asset_id: str,
    base_risk_score: float = Query(..., ge=0.0, le=1.0, description="Base risk score from GNN")
):
    """Enhance risk score with threat intelligence context."""
    try:
        ioc_service = IOCService()
        threat_context = await ioc_service.get_asset_threat_context(asset_id)
        
        # Calculate enhanced risk score
        threat_multipliers = {
            "unknown": 1.0,
            "low": 1.1,
            "medium": 1.3,
            "high": 1.6,
            "critical": 2.0
        }
        
        multiplier = threat_multipliers.get(threat_context.threat_level, 1.0)
        enhanced_risk = min(base_risk_score * multiplier, 1.0)
        
        return {
            "asset_id": asset_id,
            "base_risk_score": base_risk_score,
            "threat_level": threat_context.threat_level,
            "threat_multiplier": multiplier,
            "enhanced_risk_score": round(enhanced_risk, 3),
            "threat_context": threat_context.dict(),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Failed to enhance risk score", asset_id=asset_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Risk enhancement failed: {str(e)}")


# Admin endpoints
@app.post("/api/v1/admin/ingest-sample-data")
async def ingest_sample_data():
    """Ingest sample threat intelligence data for testing."""
    try:
        sample_count = await ingest_sample_threat_data()
        return {
            "message": "Sample data ingestion completed",
            "items_ingested": sample_count,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Failed to ingest sample data", error=str(e))
        raise HTTPException(status_code=500, detail=f"Sample data ingestion failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )
