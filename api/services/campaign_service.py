"""Campaign service."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
from api.models.campaign import Campaign, CampaignSearchRequest, CampaignSearchResponse, CampaignTimeline
from database.neo4j.connection import execute_query, execute_write_query

logger = structlog.get_logger(__name__)


class CampaignService:
    """Service for managing campaigns and timeline analysis."""
    
    def __init__(self):
        self.logger = logger.bind(service="campaign_service")
    
    async def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Get campaign by ID."""
        self.logger.info("Getting campaign", campaign_id=campaign_id)
        
        try:
            query = """
            MATCH (c:Campaign {id: $campaign_id})
            OPTIONAL MATCH (c)<-[:BELONGS_TO]-(ta:ThreatActor)
            OPTIONAL MATCH (c)-[:INVOLVES]->(ioc:IOC)
            OPTIONAL MATCH (c)-[:USES]->(ttp:TTP)
            OPTIONAL MATCH (c)-[:TARGETS]->(a:Asset)
            RETURN c, collect(DISTINCT ta) as threat_actors,
                   collect(DISTINCT ioc) as iocs,
                   collect(DISTINCT ttp) as ttps,
                   collect(DISTINCT a) as assets
            """
            
            results = execute_query(query, {"campaign_id": campaign_id})
            
            if not results:
                return None
            
            record = results[0]
            campaign_data = dict(record["c"])
            
            # Add relationships
            campaign_data["threat_actors"] = [ta["name"] for ta in record["threat_actors"] if ta]
            campaign_data["iocs"] = [ioc["id"] for ioc in record["iocs"] if ioc]
            campaign_data["ttps"] = [ttp["mitre_id"] for ttp in record["ttps"] if ttp]
            campaign_data["target_organizations"] = [asset["id"] for asset in record["assets"] if asset]
            
            return Campaign(**campaign_data)
            
        except Exception as e:
            self.logger.error("Failed to get campaign", campaign_id=campaign_id, error=str(e))
            return None
    
    async def search_campaigns(self, search_params: CampaignSearchRequest) -> CampaignSearchResponse:
        """Search for campaigns with various filters."""
        self.logger.info("Searching campaigns", search_params=search_params.dict())
        
        try:
            # Build dynamic query based on search parameters
            where_conditions = ["(c:Campaign)"]
            parameters = {}
            
            if search_params.name:
                where_conditions.append("c.name CONTAINS $name")
                parameters["name"] = search_params.name
            
            if search_params.status:
                where_conditions.append("c.status = $status")
                parameters["status"] = search_params.status.value
            
            if search_params.threat_actor:
                where_conditions.append("(c)<-[:BELONGS_TO]-(ta:ThreatActor {name: $threat_actor})")
                parameters["threat_actor"] = search_params.threat_actor
            
            if search_params.target_industry:
                where_conditions.append("$target_industry IN c.target_industries")
                parameters["target_industry"] = search_params.target_industry
            
            if search_params.start_date_from:
                where_conditions.append("c.start_date >= $start_date_from")
                parameters["start_date_from"] = search_params.start_date_from.isoformat()
            
            if search_params.start_date_to:
                where_conditions.append("c.start_date <= $start_date_to")
                parameters["start_date_to"] = search_params.start_date_to.isoformat()
            
            # Build final query
            where_clause = " AND ".join(where_conditions)
            query = f"""
            MATCH {where_clause}
            RETURN c
            ORDER BY c.start_date DESC
            SKIP $offset
            LIMIT $limit
            """
            
            parameters.update({
                "offset": search_params.offset,
                "limit": search_params.limit
            })
            
            results = execute_query(query, parameters)
            campaigns = [Campaign(**dict(record["c"])) for record in results]
            
            # Get total count for pagination
            count_query = f"""
            MATCH {where_clause}
            RETURN count(c) as total_count
            """
            count_params = {k: v for k, v in parameters.items() if k not in ["offset", "limit"]}
            count_result = execute_query(count_query, count_params)
            total_count = count_result[0]["total_count"] if count_result else 0
            
            return CampaignSearchResponse(
                campaigns=campaigns,
                total_count=total_count,
                search_params=search_params
            )
            
        except Exception as e:
            self.logger.error("Failed to search campaigns", error=str(e))
            return CampaignSearchResponse(
                campaigns=[],
                total_count=0,
                search_params=search_params
            )
    
    async def create_campaign(self, campaign: Campaign) -> Campaign:
        """Create a new campaign in the database."""
        self.logger.info("Creating campaign", campaign_id=campaign.id, name=campaign.name)
        
        try:
            query = """
            CREATE (c:Campaign {
                id: $id,
                name: $name,
                description: $description,
                start_date: $start_date,
                end_date: $end_date,
                status: $status,
                objectives: $objectives,
                target_industries: $target_industries,
                target_countries: $target_countries,
                target_organizations: $target_organizations,
                source: $source,
                tags: $tags,
                confidence: $confidence,
                context: $context
            })
            RETURN c
            """
            
            parameters = {
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
                "end_date": campaign.end_date.isoformat() if campaign.end_date else None,
                "status": campaign.status.value,
                "objectives": campaign.objectives,
                "target_industries": campaign.target_industries,
                "target_countries": campaign.target_countries,
                "target_organizations": campaign.target_organizations,
                "source": campaign.source,
                "tags": campaign.tags,
                "confidence": campaign.confidence,
                "context": campaign.context
            }
            
            result = execute_write_query(query, parameters)
            if result:
                return Campaign(**dict(result[0]["c"]))
            else:
                raise Exception("Failed to create campaign")
                
        except Exception as e:
            self.logger.error("Failed to create campaign", campaign_id=campaign.id, error=str(e))
            raise
    
    async def analyze_campaign_timeline(self, campaign_id: str) -> CampaignTimeline:
        """Analyze campaign timeline and key events."""
        self.logger.info("Analyzing campaign timeline", campaign_id=campaign_id)
        
        try:
            # Query for campaign timeline events
            timeline_query = """
            MATCH (c:Campaign {id: $campaign_id})
            OPTIONAL MATCH (c)-[:INVOLVES]->(ioc:IOC)
            OPTIONAL MATCH (c)-[:USES]->(ttp:TTP)
            OPTIONAL MATCH (c)<-[:BELONGS_TO]-(ta:ThreatActor)
            RETURN c, collect(DISTINCT ioc) as iocs,
                   collect(DISTINCT ttp) as ttps,
                   collect(DISTINCT ta) as threat_actors
            """
            
            results = execute_query(timeline_query, {"campaign_id": campaign_id})
            
            if not results:
                return CampaignTimeline(
                    campaign_id=campaign_id,
                    timeline_events=[],
                    key_milestones=[],
                    ioc_timeline=[],
                    ttp_evolution=[]
                )
            
            record = results[0]
            campaign_data = dict(record["c"])
            iocs = [dict(ioc) for ioc in record["iocs"] if ioc]
            ttps = [dict(ttp) for ttp in record["ttps"] if ttp]
            threat_actors = [dict(ta) for ta in record["threat_actors"] if ta]
            
            # Build timeline events
            timeline_events = []
            
            # Add campaign start/end events
            if campaign_data.get("start_date"):
                timeline_events.append({
                    "date": campaign_data["start_date"],
                    "event_type": "campaign_start",
                    "description": f"Campaign '{campaign_data['name']}' started",
                    "confidence": 1.0
                })
            
            if campaign_data.get("end_date"):
                timeline_events.append({
                    "date": campaign_data["end_date"],
                    "event_type": "campaign_end",
                    "description": f"Campaign '{campaign_data['name']}' ended",
                    "confidence": 1.0
                })
            
            # Add IOC events
            for ioc in iocs:
                if ioc.get("first_seen"):
                    timeline_events.append({
                        "date": ioc["first_seen"],
                        "event_type": "ioc_first_seen",
                        "description": f"IOC {ioc['type']}: {ioc['value']} first observed",
                        "confidence": ioc.get("confidence", 0.5),
                        "ioc_id": ioc["id"]
                    })
            
            # Sort timeline events by date
            timeline_events.sort(key=lambda x: x.get("date", ""))
            
            # Build key milestones
            key_milestones = []
            if timeline_events:
                key_milestones.append({
                    "milestone": "Campaign Initiation",
                    "date": timeline_events[0]["date"],
                    "description": "First campaign activity detected"
                })
            
            # Build IOC timeline
            ioc_timeline = []
            for ioc in sorted(iocs, key=lambda x: x.get("first_seen", "")):
                ioc_timeline.append({
                    "ioc_id": ioc["id"],
                    "type": ioc["type"],
                    "value": ioc["value"],
                    "first_seen": ioc.get("first_seen"),
                    "last_seen": ioc.get("last_seen"),
                    "confidence": ioc.get("confidence", 0.5)
                })
            
            # Build TTP evolution
            ttp_evolution = []
            for ttp in ttps:
                ttp_evolution.append({
                    "ttp_id": ttp["id"],
                    "mitre_id": ttp.get("mitre_id"),
                    "technique": ttp.get("technique"),
                    "tactic": ttp.get("tactic"),
                    "description": ttp.get("description")
                })
            
            return CampaignTimeline(
                campaign_id=campaign_id,
                timeline_events=timeline_events,
                key_milestones=key_milestones,
                ioc_timeline=ioc_timeline,
                ttp_evolution=ttp_evolution
            )
            
        except Exception as e:
            self.logger.error("Failed to analyze campaign timeline", campaign_id=campaign_id, error=str(e))
            return CampaignTimeline(
                campaign_id=campaign_id,
                timeline_events=[],
                key_milestones=[],
                ioc_timeline=[],
                ttp_evolution=[]
            )



