"""Threat Actor service."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
from api.models.threat_actor import ThreatActor, ThreatActorSearchRequest, ThreatActorSearchResponse, ThreatAttribution
from database.neo4j.connection import execute_query, execute_write_query

logger = structlog.get_logger(__name__)


class ThreatService:
    """Service for managing threat actors and attribution."""
    
    def __init__(self):
        self.logger = logger.bind(service="threat_service")
    
    async def get_threat_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get threat actor by ID."""
        self.logger.info("Getting threat actor", actor_id=actor_id)
        
        try:
            query = """
            MATCH (ta:ThreatActor {id: $actor_id})
            OPTIONAL MATCH (ta)-[:BELONGS_TO]->(c:Campaign)
            OPTIONAL MATCH (ta)-[:CONTROLS]->(ioc:IOC)
            OPTIONAL MATCH (ta)-[:DEVELOPS]->(m:Malware)
            RETURN ta, collect(DISTINCT c) as campaigns, 
                   collect(DISTINCT ioc) as iocs, 
                   collect(DISTINCT m) as malwares
            """
            
            results = execute_query(query, {"actor_id": actor_id})
            
            if not results:
                return None
            
            record = results[0]
            ta_data = dict(record["ta"])
            
            # Add relationships
            ta_data["campaigns"] = [c["name"] for c in record["campaigns"] if c]
            ta_data["iocs"] = [ioc["id"] for ioc in record["iocs"] if ioc]
            ta_data["malwares"] = [m["name"] for m in record["malwares"] if m]
            
            return ThreatActor(**ta_data)
            
        except Exception as e:
            self.logger.error("Failed to get threat actor", actor_id=actor_id, error=str(e))
            return None
    
    async def search_threat_actors(self, search_params: ThreatActorSearchRequest) -> ThreatActorSearchResponse:
        """Search for threat actors with various filters."""
        self.logger.info("Searching threat actors", search_params=search_params.dict())
        
        try:
            # Build dynamic query based on search parameters
            where_conditions = ["(ta:ThreatActor)"]
            parameters = {}
            
            if search_params.name:
                where_conditions.append("(ta.name CONTAINS $name OR $name IN ta.aliases)")
                parameters["name"] = search_params.name
            
            if search_params.country:
                where_conditions.append("ta.country = $country")
                parameters["country"] = search_params.country
            
            if search_params.motivation:
                where_conditions.append("ta.motivation = $motivation")
                parameters["motivation"] = search_params.motivation.value
            
            if search_params.status:
                where_conditions.append("ta.status = $status")
                parameters["status"] = search_params.status.value
            
            if search_params.campaign:
                where_conditions.append("(ta)-[:BELONGS_TO]->(c:Campaign {name: $campaign})")
                parameters["campaign"] = search_params.campaign
            
            # Build final query
            where_clause = " AND ".join(where_conditions)
            query = f"""
            MATCH {where_clause}
            RETURN ta
            ORDER BY ta.name
            SKIP $offset
            LIMIT $limit
            """
            
            parameters.update({
                "offset": search_params.offset,
                "limit": search_params.limit
            })
            
            results = execute_query(query, parameters)
            threat_actors = [ThreatActor(**dict(record["ta"])) for record in results]
            
            # Get total count for pagination
            count_query = f"""
            MATCH {where_clause}
            RETURN count(ta) as total_count
            """
            count_params = {k: v for k, v in parameters.items() if k not in ["offset", "limit"]}
            count_result = execute_query(count_query, count_params)
            total_count = count_result[0]["total_count"] if count_result else 0
            
            return ThreatActorSearchResponse(
                threat_actors=threat_actors,
                total_count=total_count,
                search_params=search_params
            )
            
        except Exception as e:
            self.logger.error("Failed to search threat actors", error=str(e))
            return ThreatActorSearchResponse(
                threat_actors=[],
                total_count=0,
                search_params=search_params
            )
    
    async def create_threat_actor(self, threat_actor: ThreatActor) -> ThreatActor:
        """Create a new threat actor in the database."""
        self.logger.info("Creating threat actor", actor_id=threat_actor.id, name=threat_actor.name)
        
        try:
            query = """
            CREATE (ta:ThreatActor {
                id: $id,
                name: $name,
                aliases: $aliases,
                country: $country,
                motivation: $motivation,
                status: $status,
                sophistication: $sophistication,
                first_seen: $first_seen,
                last_seen: $last_seen,
                source: $source,
                description: $description,
                context: $context
            })
            RETURN ta
            """
            
            parameters = {
                "id": threat_actor.id,
                "name": threat_actor.name,
                "aliases": threat_actor.aliases,
                "country": threat_actor.country,
                "motivation": threat_actor.motivation.value,
                "status": threat_actor.status.value,
                "sophistication": threat_actor.sophistication,
                "first_seen": threat_actor.first_seen.isoformat() if threat_actor.first_seen else None,
                "last_seen": threat_actor.last_seen.isoformat() if threat_actor.last_seen else None,
                "source": threat_actor.source,
                "description": threat_actor.description,
                "context": threat_actor.context
            }
            
            result = execute_write_query(query, parameters)
            if result:
                return ThreatActor(**dict(result[0]["ta"]))
            else:
                raise Exception("Failed to create threat actor")
                
        except Exception as e:
            self.logger.error("Failed to create threat actor", actor_id=threat_actor.id, error=str(e))
            raise
    
    async def attribute_threat(self, campaign_id: str) -> ThreatAttribution:
        """Attribute a campaign to threat actors."""
        self.logger.info("Attributing threat for campaign", campaign_id=campaign_id)
        
        try:
            # Query for campaign and associated threat actors
            query = """
            MATCH (c:Campaign {id: $campaign_id})
            MATCH (c)<-[:BELONGS_TO]-(ta:ThreatActor)
            OPTIONAL MATCH (ta)-[:CONTROLS]->(ioc:IOC)-[:INVOLVES]->(c)
            RETURN ta, count(ioc) as ioc_count
            ORDER BY ioc_count DESC
            """
            
            results = execute_query(query, {"campaign_id": campaign_id})
            
            if not results:
                return ThreatAttribution(
                    campaign_id=campaign_id,
                    attributed_actors=[],
                    attribution_confidence=0.0,
                    attribution_method="graph_analysis"
                )
            
            # Calculate attribution scores based on IOC count and other factors
            attributed_actors = []
            total_confidence = 0.0
            
            for record in results:
                ta_data = dict(record["ta"])
                ioc_count = record["ioc_count"]
                
                # Calculate confidence based on IOC count and actor characteristics
                confidence = min(0.3 + (ioc_count * 0.1), 1.0)
                if ta_data.get("sophistication") == "high":
                    confidence += 0.2
                if ta_data.get("status") == "active":
                    confidence += 0.1
                
                confidence = min(confidence, 1.0)
                total_confidence += confidence
                
                attributed_actors.append({
                    "actor_id": ta_data["id"],
                    "actor_name": ta_data["name"],
                    "confidence": round(confidence, 3),
                    "ioc_count": ioc_count
                })
            
            # Normalize confidence scores
            if attributed_actors:
                avg_confidence = total_confidence / len(attributed_actors)
                for actor in attributed_actors:
                    actor["confidence"] = round(actor["confidence"] / total_confidence, 3)
            else:
                avg_confidence = 0.0
            
            return ThreatAttribution(
                campaign_id=campaign_id,
                attributed_actors=attributed_actors,
                attribution_confidence=round(avg_confidence, 3),
                attribution_method="graph_analysis"
            )
            
        except Exception as e:
            self.logger.error("Failed to attribute threat", campaign_id=campaign_id, error=str(e))
            return ThreatAttribution(
                campaign_id=campaign_id,
                attributed_actors=[],
                attribution_confidence=0.0,
                attribution_method="graph_analysis"
            )



