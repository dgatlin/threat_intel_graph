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
            if where_conditions:
                where_clause = " AND ".join(where_conditions)
                query = f"""
                MATCH (ioc:IOC)
                WHERE {where_clause}
                RETURN ioc
                ORDER BY ioc.confidence DESC
                SKIP $offset
                LIMIT $limit
                """
            else:
                query = """
                MATCH (ioc:IOC)
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
            if where_conditions:
                count_query = f"""
                MATCH (ioc:IOC)
                WHERE {where_clause}
                RETURN count(ioc) as total_count
                """
            else:
                count_query = """
                MATCH (ioc:IOC)
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
    
    async def get_ioc_relationships(self, ioc_id: str, depth: int = 2) -> List[Dict[str, Any]]:
        """Get relationship data for graph-based analysis."""
        self.logger.info("Getting IOC relationships", ioc_id=ioc_id, depth=depth)
        
        try:
            query = """
            MATCH path = (ioc:IOC {id: $ioc_id})-[*1..$depth]-(connected)
            WHERE connected <> ioc
            RETURN 
                startNode(path) as source,
                endNode(path) as target,
                relationships(path) as relationships,
                length(path) as path_length
            ORDER BY path_length
            """
            
            results = execute_query(query, {"ioc_id": ioc_id, "depth": depth})
            
            relationships = []
            for record in results:
                source = dict(record["source"])
                target = dict(record["target"])
                rels = [dict(rel) for rel in record["relationships"]]
                
                # Create relationship data for graph building
                relationship_data = {
                    "source": source["id"],
                    "target": target["id"],
                    "source_type": source.get("__labels__", ["Unknown"])[0],
                    "target_type": target.get("__labels__", ["Unknown"])[0],
                    "relationships": rels,
                    "path_length": record["path_length"],
                    "properties": {
                        "source_properties": {k: v for k, v in source.items() if not k.startswith("__")},
                        "target_properties": {k: v for k, v in target.items() if not k.startswith("__")}
                    }
                }
                relationships.append(relationship_data)
            
            return relationships
            
        except Exception as e:
            self.logger.error("Failed to get IOC relationships", ioc_id=ioc_id, error=str(e))
            return []
    
    async def get_graph_export(self, node_types: Optional[List[str]] = None, 
                             relationship_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Export graph data for GNN training."""
        self.logger.info("Exporting graph data", node_types=node_types, relationship_types=relationship_types)
        
        try:
            # Build node query
            node_query = "MATCH (n)"
            if node_types:
                type_conditions = " OR ".join([f"n:{node_type}" for node_type in node_types])
                node_query += f" WHERE {type_conditions}"
            node_query += " RETURN n"
            
            nodes_result = execute_query(node_query)
            nodes = [dict(record["n"]) for record in nodes_result]
            
            # Build relationship query
            rel_query = "MATCH (a)-[r]->(b)"
            if relationship_types:
                rel_conditions = " OR ".join([f"type(r) = '{rel_type}'" for rel_type in relationship_types])
                rel_query += f" WHERE {rel_conditions}"
            rel_query += " RETURN a, r, b"
            
            rels_result = execute_query(rel_query)
            relationships = []
            for record in rels_result:
                rel_data = {
                    "source": dict(record["a"])["id"],
                    "target": dict(record["b"])["id"],
                    "type": type(record["r"]).__name__,
                    "properties": dict(record["r"])
                }
                relationships.append(rel_data)
            
            return {
                "nodes": nodes,
                "relationships": relationships,
                "node_count": len(nodes),
                "relationship_count": len(relationships),
                "export_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error("Failed to export graph data", error=str(e))
            return {"nodes": [], "relationships": [], "error": str(e)}
    
    
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