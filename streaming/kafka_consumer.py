"""Kafka consumer for threat intelligence streaming."""

import json
import asyncio
from typing import Dict, Any, Callable, List
from datetime import datetime
import structlog
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from config.settings import settings

logger = structlog.get_logger(__name__)


class ThreatIntelligenceConsumer:
    """Kafka consumer for processing threat intelligence data."""
    
    def __init__(self, topics: List[str], group_id: str = "threat_intel_consumer"):
        self.logger = logger.bind(service="kafka_consumer")
        self.topics = topics
        self.group_id = group_id
        self.consumer = None
        self.message_handlers = {}
        self.running = False
        self._connect()
    
    def _connect(self):
        """Connect to Kafka cluster."""
        try:
            self.consumer = KafkaConsumer(
                *self.topics,
                bootstrap_servers=settings.kafka_brokers.split(','),
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                key_deserializer=lambda m: m.decode('utf-8') if m else None,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                auto_commit_interval_ms=1000,
                session_timeout_ms=30000,
                heartbeat_interval_ms=10000
            )
            self.logger.info("Connected to Kafka cluster", topics=self.topics, group_id=self.group_id)
        except Exception as e:
            self.logger.error("Failed to connect to Kafka", error=str(e))
            raise
    
    def register_handler(self, topic: str, handler: Callable[[Dict[str, Any]], None]):
        """Register a message handler for a specific topic."""
        self.message_handlers[topic] = handler
        self.logger.info("Registered handler for topic", topic=topic)
    
    async def start_consuming(self):
        """Start consuming messages from Kafka topics."""
        if not self.consumer:
            self._connect()
        
        self.running = True
        self.logger.info("Starting Kafka consumer", topics=self.topics)
        
        try:
            for message in self.consumer:
                if not self.running:
                    break
                
                await self._process_message(message)
                
        except KafkaError as e:
            self.logger.error("Kafka consumer error", error=str(e))
        except Exception as e:
            self.logger.error("Unexpected consumer error", error=str(e))
        finally:
            self.stop_consuming()
    
    async def _process_message(self, message):
        """Process a single Kafka message."""
        try:
            topic = message.topic
            key = message.key
            value = message.value
            
            self.logger.info(
                "Processing message",
                topic=topic,
                key=key,
                partition=message.partition,
                offset=message.offset
            )
            
            # Get handler for topic
            handler = self.message_handlers.get(topic)
            if handler:
                await handler(value)
            else:
                self.logger.warning("No handler registered for topic", topic=topic)
                
        except Exception as e:
            self.logger.error("Failed to process message", error=str(e))
    
    def stop_consuming(self):
        """Stop consuming messages."""
        self.running = False
        if self.consumer:
            self.consumer.close()
        self.logger.info("Kafka consumer stopped")
    
    def close(self):
        """Close Kafka consumer."""
        self.stop_consuming()


class ThreatIntelligenceProcessor:
    """Process threat intelligence messages from Kafka."""
    
    def __init__(self):
        self.logger = logger.bind(service="threat_processor")
        self.consumer = None
    
    async def start_processing(self):
        """Start processing threat intelligence messages."""
        topics = [settings.kafka_topic_threat_intel, settings.kafka_topic_ioc_correlation]
        self.consumer = ThreatIntelligenceConsumer(topics, "threat_intel_processor")
        
        # Register handlers
        self.consumer.register_handler(settings.kafka_topic_threat_intel, self.process_threat_intelligence)
        self.consumer.register_handler(settings.kafka_topic_ioc_correlation, self.process_ioc_correlation)
        
        # Start consuming
        await self.consumer.start_consuming()
    
    async def process_threat_intelligence(self, message: Dict[str, Any]):
        """Process threat intelligence message."""
        try:
            self.logger.info("Processing threat intelligence message", message_id=message.get("data", {}).get("id"))
            
            # Extract threat data
            threat_data = message.get("data", {})
            message_type = threat_data.get("type", "unknown")
            
            # Process based on message type
            if message_type == "ioc":
                await self._process_ioc_data(threat_data)
            elif message_type == "threat_actor":
                await self._process_threat_actor_data(threat_data)
            elif message_type == "campaign":
                await self._process_campaign_data(threat_data)
            else:
                self.logger.warning("Unknown message type", message_type=message_type)
                
        except Exception as e:
            self.logger.error("Failed to process threat intelligence message", error=str(e))
    
    async def process_ioc_correlation(self, message: Dict[str, Any]):
        """Process IOC correlation message."""
        try:
            self.logger.info("Processing IOC correlation message", message_id=message.get("data", {}).get("id"))
            
            # Extract correlation data
            correlation_data = message.get("data", {})
            
            # Process correlation (e.g., update asset risk scores, trigger alerts)
            await self._process_correlation_data(correlation_data)
            
        except Exception as e:
            self.logger.error("Failed to process IOC correlation message", error=str(e))
    
    async def _process_ioc_data(self, ioc_data: Dict[str, Any]):
        """Process IOC data."""
        self.logger.info("Processing IOC data", ioc_id=ioc_data.get("id"))
        
        try:
            from database.neo4j.connection import execute_write_query
            
            # Create or update IOC in Neo4j
            query = """
            MERGE (ioc:IOC {id: $id})
            SET ioc.type = $type,
                ioc.value = $value,
                ioc.category = $category,
                ioc.confidence = $confidence,
                ioc.source = $source,
                ioc.first_seen = $first_seen,
                ioc.last_seen = $last_seen
            RETURN ioc
            """
            
            result = execute_write_query(query, {
                "id": ioc_data.get("id"),
                "type": ioc_data.get("type"),
                "value": ioc_data.get("value"),
                "category": ioc_data.get("category", "unknown"),
                "confidence": ioc_data.get("confidence", 0.5),
                "source": ioc_data.get("source", "kafka"),
                "first_seen": ioc_data.get("first_seen", datetime.utcnow().isoformat()),
                "last_seen": datetime.utcnow().isoformat()
            })
            
            if result:
                self.logger.info("IOC stored in Neo4j", ioc_id=ioc_data.get("id"))
                
                # Create relationships if threat actors are specified
                if "threat_actors" in ioc_data:
                    for actor_name in ioc_data["threat_actors"]:
                        relationship_query = """
                        MATCH (ioc:IOC {id: $ioc_id})
                        MATCH (ta:ThreatActor {name: $actor_name})
                        MERGE (ioc)-[:USED_BY]->(ta)
                        """
                        execute_write_query(relationship_query, {
                            "ioc_id": ioc_data.get("id"),
                            "actor_name": actor_name
                        })
                
                # Create relationships if campaigns are specified
                if "campaigns" in ioc_data:
                    for campaign_name in ioc_data["campaigns"]:
                        relationship_query = """
                        MATCH (ioc:IOC {id: $ioc_id})
                        MATCH (c:Campaign {name: $campaign_name})
                        MERGE (ioc)-[:SEEN_IN]->(c)
                        """
                        execute_write_query(relationship_query, {
                            "ioc_id": ioc_data.get("id"),
                            "campaign_name": campaign_name
                        })
                        
        except Exception as e:
            self.logger.error("Failed to store IOC in Neo4j", error=str(e))
    
    async def _process_threat_actor_data(self, actor_data: Dict[str, Any]):
        """Process threat actor data."""
        self.logger.info("Processing threat actor data", actor_id=actor_data.get("id"))
        
        try:
            from database.neo4j.connection import execute_write_query
            
            # Create or update threat actor in Neo4j
            query = """
            MERGE (ta:ThreatActor {id: $id})
            SET ta.name = $name,
                ta.aliases = $aliases,
                ta.country = $country,
                ta.motivation = $motivation,
                ta.status = $status,
                ta.sophistication = $sophistication,
                ta.source = $source,
                ta.first_seen = $first_seen,
                ta.last_seen = $last_seen
            RETURN ta
            """
            
            result = execute_write_query(query, {
                "id": actor_data.get("id"),
                "name": actor_data.get("name"),
                "aliases": actor_data.get("aliases", []),
                "country": actor_data.get("country", "unknown"),
                "motivation": actor_data.get("motivation", "unknown"),
                "status": actor_data.get("status", "active"),
                "sophistication": actor_data.get("sophistication", "unknown"),
                "source": actor_data.get("source", "kafka"),
                "first_seen": actor_data.get("first_seen", datetime.utcnow().isoformat()),
                "last_seen": datetime.utcnow().isoformat()
            })
            
            if result:
                self.logger.info("Threat actor stored in Neo4j", actor_id=actor_data.get("id"))
                
                # Create relationships if campaigns are specified
                if "campaigns" in actor_data:
                    for campaign_name in actor_data["campaigns"]:
                        relationship_query = """
                        MATCH (ta:ThreatActor {id: $actor_id})
                        MATCH (c:Campaign {name: $campaign_name})
                        MERGE (ta)-[:BELONGS_TO]->(c)
                        """
                        execute_write_query(relationship_query, {
                            "actor_id": actor_data.get("id"),
                            "campaign_name": campaign_name
                        })
                        
        except Exception as e:
            self.logger.error("Failed to store threat actor in Neo4j", error=str(e))
    
    async def _process_campaign_data(self, campaign_data: Dict[str, Any]):
        """Process campaign data."""
        self.logger.info("Processing campaign data", campaign_id=campaign_data.get("id"))
        
        try:
            from database.neo4j.connection import execute_write_query
            
            # Create or update campaign in Neo4j
            query = """
            MERGE (c:Campaign {id: $id})
            SET c.name = $name,
                c.description = $description,
                c.status = $status,
                c.objectives = $objectives,
                c.start_date = $start_date,
                c.end_date = $end_date,
                c.source = $source
            RETURN c
            """
            
            result = execute_write_query(query, {
                "id": campaign_data.get("id"),
                "name": campaign_data.get("name"),
                "description": campaign_data.get("description", ""),
                "status": campaign_data.get("status", "active"),
                "objectives": campaign_data.get("objectives", []),
                "start_date": campaign_data.get("start_date"),
                "end_date": campaign_data.get("end_date"),
                "source": campaign_data.get("source", "kafka")
            })
            
            if result:
                self.logger.info("Campaign stored in Neo4j", campaign_id=campaign_data.get("id"))
                
                # Create relationships if IOCs are specified
                if "iocs" in campaign_data:
                    for ioc_id in campaign_data["iocs"]:
                        relationship_query = """
                        MATCH (c:Campaign {id: $campaign_id})
                        MATCH (ioc:IOC {id: $ioc_id})
                        MERGE (c)-[:INVOLVES]->(ioc)
                        """
                        execute_write_query(relationship_query, {
                            "campaign_id": campaign_data.get("id"),
                            "ioc_id": ioc_id
                        })
                        
        except Exception as e:
            self.logger.error("Failed to store campaign in Neo4j", error=str(e))
    
    async def _process_correlation_data(self, correlation_data: Dict[str, Any]):
        """Process correlation data."""
        self.logger.info("Processing correlation data", correlation_id=correlation_data.get("id"))
        
        try:
            from database.neo4j.connection import execute_write_query
            
            # Process asset-IOC correlations
            if "asset_id" in correlation_data and "ioc_id" in correlation_data:
                # Create exposure relationship between asset and IOC
                exposure_query = """
                MATCH (a:Asset {id: $asset_id})
                MATCH (ioc:IOC {id: $ioc_id})
                MERGE (a)-[:EXPOSED_TO]->(ioc)
                SET a.last_updated = $timestamp
                RETURN a, ioc
                """
                
                result = execute_write_query(exposure_query, {
                    "asset_id": correlation_data["asset_id"],
                    "ioc_id": correlation_data["ioc_id"],
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                if result:
                    self.logger.info("Asset-IOC correlation created", 
                                   asset_id=correlation_data["asset_id"],
                                   ioc_id=correlation_data["ioc_id"])
            
            # Update asset risk score based on threat intelligence
            if "asset_id" in correlation_data and "threat_level" in correlation_data:
                risk_update_query = """
                MATCH (a:Asset {id: $asset_id})
                SET a.threat_level = $threat_level,
                    a.risk_score = $risk_score,
                    a.last_updated = $timestamp
                RETURN a
                """
                
                threat_level = correlation_data["threat_level"]
                risk_multipliers = {
                    "unknown": 1.0,
                    "low": 1.1,
                    "medium": 1.3,
                    "high": 1.6,
                    "critical": 2.0
                }
                
                base_risk = correlation_data.get("base_risk_score", 0.5)
                enhanced_risk = min(base_risk * risk_multipliers.get(threat_level, 1.0), 1.0)
                
                execute_write_query(risk_update_query, {
                    "asset_id": correlation_data["asset_id"],
                    "threat_level": threat_level,
                    "risk_score": enhanced_risk,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                self.logger.info("Asset risk score updated", 
                               asset_id=correlation_data["asset_id"],
                               threat_level=threat_level,
                               risk_score=enhanced_risk)
                
        except Exception as e:
            self.logger.error("Failed to process correlation data", error=str(e))


# Global processor instance (lazy initialization)
threat_processor = None

def get_threat_processor():
    """Get or create the global threat processor instance."""
    global threat_processor
    if threat_processor is None:
        threat_processor = ThreatIntelligenceProcessor()
    return threat_processor


async def start_threat_intelligence_processing(timeout: int = None):
    """Start threat intelligence processing from Kafka."""
    processor = get_threat_processor()
    consumer = ThreatIntelligenceConsumer()
    processor.consumer = consumer
    
    try:
        await consumer.consume_messages(timeout=timeout)
    finally:
        consumer.close()

