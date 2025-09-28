"""Initialize Neo4j database with threat intelligence schema."""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.neo4j.connection import execute_write_query
from config.logging import configure_logging, get_logger

# Configure logging
configure_logging()
logger = get_logger(__name__)


def init_database():
    """Initialize the Neo4j database with schema and constraints."""
    logger.info("Initializing Neo4j database schema")
    
    try:
        # Read and execute node constraints
        nodes_schema_path = project_root / "database" / "schemas" / "nodes.cypher"
        with open(nodes_schema_path, 'r') as f:
            nodes_queries = f.read().split(';')
        
        for query in nodes_queries:
            query = query.strip()
            if query:
                try:
                    execute_write_query(query)
                    logger.info("Executed node constraint query", query=query[:100] + "...")
                except Exception as e:
                    logger.warning("Failed to execute node constraint", query=query[:100], error=str(e))
        
        # Read and execute relationship definitions
        relationships_schema_path = project_root / "database" / "schemas" / "relationships.cypher"
        with open(relationships_schema_path, 'r') as f:
            relationship_queries = f.read().split(';')
        
        for query in relationship_queries:
            query = query.strip()
            if query:
                try:
                    execute_write_query(query)
                    logger.info("Executed relationship query", query=query[:100] + "...")
                except Exception as e:
                    logger.warning("Failed to execute relationship query", query=query[:100], error=str(e))
        
        # Create sample data for testing
        create_sample_data()
        
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise


def create_sample_data():
    """Create sample threat intelligence data for testing."""
    logger.info("Creating sample threat intelligence data")
    
    try:
        # Sample threat actors
        threat_actors = [
            {
                "id": "ta_apt29",
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes"],
                "country": "Russia",
                "motivation": "espionage",
                "status": "active",
                "sophistication": "high",
                "source": "sample"
            },
            {
                "id": "ta_lazarus",
                "name": "Lazarus Group",
                "aliases": ["HIDDEN COBRA"],
                "country": "North Korea",
                "motivation": "financial",
                "status": "active",
                "sophistication": "high",
                "source": "sample"
            }
        ]
        
        for ta in threat_actors:
            query = """
            CREATE (ta:ThreatActor {
                id: $id,
                name: $name,
                aliases: $aliases,
                country: $country,
                motivation: $motivation,
                status: $status,
                sophistication: $sophistication,
                source: $source
            })
            """
            execute_write_query(query, ta)
        
        # Sample campaigns
        campaigns = [
            {
                "id": "camp_operation_cozy_bear",
                "name": "Operation Cozy Bear",
                "description": "Long-term espionage campaign targeting government and corporate networks",
                "status": "active",
                "source": "sample"
            },
            {
                "id": "camp_cryptocurrency_theft",
                "name": "Cryptocurrency Exchange Theft Campaign",
                "description": "Campaign targeting cryptocurrency exchanges and wallets",
                "status": "active",
                "source": "sample"
            }
        ]
        
        for campaign in campaigns:
            query = """
            CREATE (c:Campaign {
                id: $id,
                name: $name,
                description: $description,
                status: $status,
                source: $source
            })
            """
            execute_write_query(query, campaign)
        
        # Sample IOCs
        iocs = [
            {
                "id": "ioc_malicious_domain_1",
                "type": "domain",
                "value": "malicious-site.com",
                "category": "attack_infrastructure",
                "confidence": 0.9,
                "source": "sample",
                "threat_actors": ["APT29"],
                "campaigns": ["Operation Cozy Bear"]
            },
            {
                "id": "ioc_suspicious_ip_1",
                "type": "ip_address",
                "value": "192.168.1.100",
                "category": "command_and_control",
                "confidence": 0.8,
                "source": "sample",
                "threat_actors": ["Lazarus Group"],
                "campaigns": ["Cryptocurrency Exchange Theft Campaign"]
            },
            {
                "id": "ioc_malware_hash_1",
                "type": "hash",
                "value": "a1b2c3d4e5f6789012345678901234567890abcd",
                "category": "malware",
                "confidence": 0.95,
                "source": "sample",
                "threat_actors": ["APT29"],
                "campaigns": ["Operation Cozy Bear"]
            }
        ]
        
        for ioc in iocs:
            query = """
            CREATE (ioc:IOC {
                id: $id,
                type: $type,
                value: $value,
                category: $category,
                confidence: $confidence,
                source: $source
            })
            """
            execute_write_query(query, ioc)
        
        # Sample assets (for GNN integration)
        assets = [
            {
                "id": "asset_web_server_01",
                "name": "Web Server 01",
                "type": "server",
                "environment": "production",
                "ip_address": "10.0.1.10"
            },
            {
                "id": "asset_database_01",
                "name": "Database Server 01",
                "type": "database",
                "environment": "production",
                "ip_address": "10.0.1.20"
            }
        ]
        
        for asset in assets:
            query = """
            CREATE (a:Asset {
                id: $id,
                name: $name,
                type: $type,
                environment: $environment,
                ip_address: $ip_address
            })
            """
            execute_write_query(query, asset)
        
        # Create relationships
        relationship_queries = [
            # Threat actor relationships
            "MATCH (ta:ThreatActor {id: 'ta_apt29'}), (c:Campaign {id: 'camp_operation_cozy_bear'}) CREATE (ta)-[:BELONGS_TO]->(c)",
            "MATCH (ta:ThreatActor {id: 'ta_lazarus'}), (c:Campaign {id: 'camp_cryptocurrency_theft'}) CREATE (ta)-[:BELONGS_TO]->(c)",
            
            # IOC relationships
            "MATCH (ioc:IOC {id: 'ioc_malicious_domain_1'}), (ta:ThreatActor {id: 'ta_apt29'}) CREATE (ioc)-[:USED_BY]->(ta)",
            "MATCH (ioc:IOC {id: 'ioc_suspicious_ip_1'}), (ta:ThreatActor {id: 'ta_lazarus'}) CREATE (ioc)-[:USED_BY]->(ta)",
            "MATCH (ioc:IOC {id: 'ioc_malware_hash_1'}), (ta:ThreatActor {id: 'ta_apt29'}) CREATE (ioc)-[:USED_BY]->(ta)",
            
            # Campaign relationships
            "MATCH (c:Campaign {id: 'camp_operation_cozy_bear'}), (ioc:IOC {id: 'ioc_malicious_domain_1'}) CREATE (c)-[:INVOLVES]->(ioc)",
            "MATCH (c:Campaign {id: 'camp_cryptocurrency_theft'}), (ioc:IOC {id: 'ioc_suspicious_ip_1'}) CREATE (c)-[:INVOLVES]->(ioc)",
            
            # Asset relationships (for GNN integration)
            "MATCH (a:Asset {id: 'asset_web_server_01'}), (ioc:IOC {id: 'ioc_malicious_domain_1'}) CREATE (a)-[:EXPOSED_TO]->(ioc)",
            "MATCH (a:Asset {id: 'asset_database_01'}), (ioc:IOC {id: 'ioc_suspicious_ip_1'}) CREATE (a)-[:EXPOSED_TO]->(ioc)"
        ]
        
        for query in relationship_queries:
            execute_write_query(query)
        
        logger.info("Sample data created successfully")
        
    except Exception as e:
        logger.error("Failed to create sample data", error=str(e))
        raise


if __name__ == "__main__":
    init_database()
