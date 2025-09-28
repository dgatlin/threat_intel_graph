"""IOC (Indicator of Compromise) service."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
from api.models.ioc import IOC, IOCSearchRequest, IOCSearchResponse, AssetThreatContext
from database.neo4j.connection import execute_query, execute_write_query

logger = structlog.get_logger(__name__)


class IOCService:
    """Service for managing IOCs and threat intelligence."""
    
    def __init__(self):
        self.logger = logger.bind(service="ioc_service")
    
    async def get_asset_threat_context(self, asset_id: str) -> AssetThreatContext:
        """Get threat intelligence context for a specific asset."""
        self.logger.info("Getting threat context for asset", asset_id=asset_id)
        
        try:
            # Query for IOCs associated with the asset
            ioc_query = """
            MATCH (a:Asset {id: $asset_id})
            MATCH (a)-[:EXPOSED_TO|:OBSERVED_ON]-(ioc:IOC)
            OPTIONAL MATCH (ioc)-[:USED_BY]->(ta:ThreatActor)
            OPTIONAL MATCH (ioc)-[:INVOLVES]->(c:Campaign)
            OPTIONAL MATCH (ioc)-[:ASSOCIATED_WITH]->(m:Malware)
            OPTIONAL MATCH (ioc)-[:USED_BY]->(ta2:ThreatActor)-[:USES]->(ttp:TTP)
            RETURN DISTINCT ioc, ta, c, m, ttp
            ORDER BY ioc.confidence DESC
            """
            
            results = execute_query(ioc_query, {"asset_id": asset_id})
            
            if not results:
                return AssetThreatContext(
                    asset_id=asset_id,
                    threat_level="unknown",
                    confidence=0.0
                )
            
            # Process results
            iocs = []
            threat_actors = set()
            campaigns = set()
            ttps = set()
            max_confidence = 0.0
            
            for record in results:
                ioc_data = dict(record["ioc"])
                iocs.append(IOC(**ioc_data))
                
                if record["ta"]:
                    threat_actors.add(record["ta"]["name"])
                if record["c"]:
                    campaigns.add(record["c"]["name"])
                if record["ttp"]:
                    ttps.add(record["ttp"]["mitre_id"])
                
                max_confidence = max(max_confidence, ioc_data.get("confidence", 0.0))
            
            # Determine threat level based on confidence and IOC count
            threat_level = self._calculate_threat_level(len(iocs), max_confidence)
            
            return AssetThreatContext(
                asset_id=asset_id,
                threat_level=threat_level,
                threat_actors=list(threat_actors),
                iocs=iocs,
                campaigns=list(campaigns),
                ttps=list(ttps),
                confidence=max_confidence
            )
            
        except Exception as e:
            self.logger.error("Failed to get asset threat context", asset_id=asset_id, error=str(e))
            return AssetThreatContext(
                asset_id=asset_id,
                threat_level="unknown",
                confidence=0.0
            )
    
    async def search_iocs(self, search_params: IOCSearchRequest) -> IOCSearchResponse:
        """Search for IOCs with various filters."""
        self.logger.info("Searching IOCs", search_params=search_params.dict())
        
        try:
            # Build dynamic query based on search parameters
            where_conditions = []
            parameters = {}
            
            if search_params.asset_id:
                where_conditions.append("(a:Asset {id: $asset_id})-[:EXPOSED_TO|:OBSERVED_ON]-(ioc:IOC)")
                parameters["asset_id"] = search_params.asset_id
            else:
                where_conditions.append("(ioc:IOC)")
            
            if search_params.ioc_type:
                where_conditions.append("ioc.type = $ioc_type")
                parameters["ioc_type"] = search_params.ioc_type.value
            
            if search_params.threat_actor:
                where_conditions.append("(ioc)-[:USED_BY]->(ta:ThreatActor {name: $threat_actor})")
                parameters["threat_actor"] = search_params.threat_actor
            
            if search_params.campaign:
                where_conditions.append("(ioc)-[:INVOLVES]->(c:Campaign {name: $campaign})")
                parameters["campaign"] = search_params.campaign
            
            if search_params.confidence_min is not None:
                where_conditions.append("ioc.confidence >= $confidence_min")
                parameters["confidence_min"] = search_params.confidence_min
            
            # Build final query
            where_clause = " AND ".join(where_conditions)
            query = f"""
            MATCH {where_clause}
            RETURN ioc
            ORDER BY ioc.confidence DESC
            SKIP $offset
            LIMIT $limit
            """
            
            parameters.update({
                "offset": search_params.offset,
                "limit": search_params.limit
            })
            
            results = execute_query(query, parameters)
            iocs = [IOC(**dict(record["ioc"])) for record in results]
            
            # Get total count for pagination
            count_query = f"""
            MATCH {where_clause}
            RETURN count(ioc) as total_count
            """
            count_params = {k: v for k, v in parameters.items() if k not in ["offset", "limit"]}
            count_result = execute_query(count_query, count_params)
            total_count = count_result[0]["total_count"] if count_result else 0
            
            return IOCSearchResponse(
                iocs=iocs,
                total_count=total_count,
                search_params=search_params
            )
            
        except Exception as e:
            self.logger.error("Failed to search IOCs", error=str(e))
            return IOCSearchResponse(
                iocs=[],
                total_count=0,
                search_params=search_params
            )
    
    async def create_ioc(self, ioc: IOC) -> IOC:
        """Create a new IOC in the database."""
        self.logger.info("Creating IOC", ioc_id=ioc.id, ioc_type=ioc.type)
        
        try:
            query = """
            CREATE (ioc:IOC {
                id: $id,
                type: $type,
                value: $value,
                category: $category,
                confidence: $confidence,
                first_seen: $first_seen,
                last_seen: $last_seen,
                source: $source,
                description: $description,
                context: $context
            })
            RETURN ioc
            """
            
            parameters = {
                "id": ioc.id,
                "type": ioc.type.value,
                "value": ioc.value,
                "category": ioc.category.value,
                "confidence": ioc.confidence,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "source": ioc.source,
                "description": ioc.description,
                "context": ioc.context
            }
            
            result = execute_write_query(query, parameters)
            if result:
                return IOC(**dict(result[0]["ioc"]))
            else:
                raise Exception("Failed to create IOC")
                
        except Exception as e:
            self.logger.error("Failed to create IOC", ioc_id=ioc.id, error=str(e))
            raise
    
    async def correlate_ioc_with_asset(self, ioc_id: str, asset_id: str) -> bool:
        """Correlate an IOC with an asset."""
        self.logger.info("Correlating IOC with asset", ioc_id=ioc_id, asset_id=asset_id)
        
        try:
            query = """
            MATCH (ioc:IOC {id: $ioc_id})
            MATCH (a:Asset {id: $asset_id})
            CREATE (a)-[:EXPOSED_TO]->(ioc)
            RETURN ioc, a
            """
            
            result = execute_write_query(query, {"ioc_id": ioc_id, "asset_id": asset_id})
            return bool(result)
            
        except Exception as e:
            self.logger.error("Failed to correlate IOC with asset", 
                            ioc_id=ioc_id, asset_id=asset_id, error=str(e))
            return False
    
    def _calculate_threat_level(self, ioc_count: int, max_confidence: float) -> str:
        """Calculate threat level based on IOC count and confidence."""
        if ioc_count == 0:
            return "unknown"
        elif ioc_count >= 10 and max_confidence >= 0.8:
            return "critical"
        elif ioc_count >= 5 and max_confidence >= 0.6:
            return "high"
        elif ioc_count >= 2 and max_confidence >= 0.4:
            return "medium"
        else:
            return "low"