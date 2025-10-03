#!/usr/bin/env python3
"""Test Kafka integration logic without requiring a running Kafka broker."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.logging import configure_logging, get_logger
from database.neo4j.connection import neo4j_connection, execute_write_query

# Configure logging
configure_logging()
logger = get_logger(__name__)


class MockKafkaProducer:
    """Mock Kafka producer for testing."""
    
    def __init__(self):
        self.sent_messages = []
        self.logger = logger.bind(service="mock_kafka_producer")
    
    async def send_threat_intelligence(self, threat_data: Dict[str, Any], topic: str = "threat_intelligence") -> bool:
        """Mock sending threat intelligence to Kafka."""
        message = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "mock_producer",
            "data": threat_data
        }
        
        self.sent_messages.append({
            "topic": topic,
            "message": message,
            "key": threat_data.get("id", "unknown")
        })
        
        self.logger.info("Mock message sent to Kafka", topic=topic, key=threat_data.get("id", "unknown"))
        return True
    
    def get_sent_messages(self) -> List[Dict[str, Any]]:
        """Get all sent messages for verification."""
        return self.sent_messages


class MockKafkaProcessor:
    """Mock Kafka processor that simulates Neo4j integration."""
    
    def __init__(self):
        self.logger = logger.bind(service="mock_kafka_processor")
        self.processed_messages = []
    
    async def process_threat_intelligence(self, message: Dict[str, Any]):
        """Process threat intelligence message and store in Neo4j."""
        try:
            threat_data = message.get("data", {})
            message_type = threat_data.get("type", "unknown")
            
            self.logger.info("Processing threat intelligence message", 
                           message_id=threat_data.get("id"),
                           message_type=message_type)
            
            # Process based on message type
            if message_type == "ioc":
                await self._process_ioc_data(threat_data)
            elif message_type == "threat_actor":
                await self._process_threat_actor_data(threat_data)
            elif message_type == "campaign":
                await self._process_campaign_data(threat_data)
            else:
                self.logger.warning("Unknown message type", message_type=message_type)
            
            self.processed_messages.append(threat_data)
            
        except Exception as e:
            self.logger.error("Failed to process threat intelligence message", error=str(e))
    
    async def _process_ioc_data(self, ioc_data: Dict[str, Any]):
        """Process IOC data and store in Neo4j."""
        self.logger.info("Processing IOC data", ioc_id=ioc_data.get("id"))
        
        try:
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
                "source": ioc_data.get("source", "mock_kafka"),
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
                
        except Exception as e:
            self.logger.error("Failed to store IOC in Neo4j", error=str(e))
    
    async def _process_threat_actor_data(self, actor_data: Dict[str, Any]):
        """Process threat actor data and store in Neo4j."""
        self.logger.info("Processing threat actor data", actor_id=actor_data.get("id"))
        
        try:
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
                "source": actor_data.get("source", "mock_kafka"),
                "first_seen": actor_data.get("first_seen", datetime.utcnow().isoformat()),
                "last_seen": datetime.utcnow().isoformat()
            })
            
            if result:
                self.logger.info("Threat actor stored in Neo4j", actor_id=actor_data.get("id"))
                
        except Exception as e:
            self.logger.error("Failed to store threat actor in Neo4j", error=str(e))
    
    async def _process_campaign_data(self, campaign_data: Dict[str, Any]):
        """Process campaign data and store in Neo4j."""
        self.logger.info("Processing campaign data", campaign_id=campaign_data.get("id"))
        
        try:
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
                "source": campaign_data.get("source", "mock_kafka")
            })
            
            if result:
                self.logger.info("Campaign stored in Neo4j", campaign_id=campaign_data.get("id"))
                
        except Exception as e:
            self.logger.error("Failed to store campaign in Neo4j", error=str(e))


async def test_mock_kafka_integration():
    """Test the Kafka integration logic with mock components."""
    logger.info("Testing mock Kafka integration...")
    
    # Create mock components
    producer = MockKafkaProducer()
    processor = MockKafkaProcessor()
    
    # Test data
    test_messages = [
        {
            "id": "mock_ioc_001",
            "type": "ioc",
            "value": "mock-malicious-domain.com",
            "category": "attack_infrastructure",
            "confidence": 0.9,
            "source": "mock_test",
            "threat_actors": ["Mock Threat Actor"],
            "campaigns": ["Mock Campaign"]
        },
        {
            "id": "mock_actor_001",
            "type": "threat_actor",
            "name": "Mock Threat Actor",
            "aliases": ["MockActor", "MA001"],
            "country": "Unknown",
            "motivation": "testing",
            "status": "active",
            "sophistication": "medium",
            "source": "mock_test",
            "campaigns": ["Mock Campaign"]
        },
        {
            "id": "mock_campaign_001",
            "type": "campaign",
            "name": "Mock Campaign",
            "description": "A mock campaign for testing Kafka integration",
            "status": "active",
            "objectives": ["testing", "validation"],
            "source": "mock_test",
            "iocs": ["mock_ioc_001"]
        }
    ]
    
    # Test producer
    logger.info("Testing mock Kafka producer...")
    producer_results = []
    for message in test_messages:
        success = await producer.send_threat_intelligence(message)
        producer_results.append(success)
    
    producer_success = sum(producer_results)
    logger.info(f"Producer test: {producer_success}/{len(test_messages)} messages sent")
    
    # Test processor
    logger.info("Testing mock Kafka processor...")
    processor_results = []
    for message_data in test_messages:
        kafka_message = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "mock_producer",
            "data": message_data
        }
        await processor.process_threat_intelligence(kafka_message)
        processor_results.append(True)  # If no exception, consider it successful
    
    processor_success = sum(processor_results)
    logger.info(f"Processor test: {processor_success}/{len(test_messages)} messages processed")
    
    # Verify data in Neo4j
    logger.info("Verifying data in Neo4j...")
    
    with neo4j_connection.get_session() as session:
        # Check IOCs
        result = session.run('MATCH (ioc:IOC) WHERE ioc.source = "mock_kafka" RETURN count(ioc) as count')
        ioc_count = result.single()["count"]
        
        # Check threat actors
        result = session.run('MATCH (ta:ThreatActor) WHERE ta.source = "mock_kafka" RETURN count(ta) as count')
        actor_count = result.single()["count"]
        
        # Check campaigns
        result = session.run('MATCH (c:Campaign) WHERE c.source = "mock_kafka" RETURN count(c) as count')
        campaign_count = result.single()["count"]
    
    logger.info(f"Neo4j verification: {ioc_count} IOCs, {actor_count} threat actors, {campaign_count} campaigns")
    
    # Overall success
    overall_success = (
        producer_success == len(test_messages) and
        processor_success == len(test_messages) and
        ioc_count >= 1 and
        actor_count >= 1 and
        campaign_count >= 1
    )
    
    return overall_success


async def test_abuse_ch_feed_integration():
    """Test abuse.ch feed integration with mock Kafka."""
    logger.info("Testing abuse.ch feed integration...")
    
    try:
        from data.ingestion.abuse_ch_feeds import AbuseChFeedIngestion
        
        # Create abuse.ch feed service
        abuse_ch_service = AbuseChFeedIngestion()
        
        # Ingest some data
        logger.info("Ingesting abuse.ch feeds...")
        abuse_ch_results = await abuse_ch_service.ingest_all_feeds()
        abuse_ch_data = abuse_ch_results.get("feodo", []) + abuse_ch_results.get("sslbl", []) + abuse_ch_results.get("urlhaus", [])
        
        if abuse_ch_data:
            logger.info(f"Retrieved {len(abuse_ch_data)} abuse.ch entries")
            
            # Convert to Kafka format and process
            mock_processor = MockKafkaProcessor()
            
            processed_count = 0
            for item in abuse_ch_data[:5]:  # Process first 5 items
                # Convert to IOC format
                ioc_data = {
                    "id": f"abuse_ch_{hash(item.get('value', ''))}",
                    "type": "ioc",
                    "value": item.get("value", ""),
                    "category": item.get("category", "suspicious"),
                    "confidence": 0.8,
                    "source": "abuse_ch_mock",
                    "first_seen": item.get("first_seen"),
                    "last_seen": datetime.utcnow().isoformat()
                }
                
                # Create Kafka message
                kafka_message = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "abuse_ch_feed",
                    "data": ioc_data
                }
                
                await mock_processor.process_threat_intelligence(kafka_message)
                processed_count += 1
            
            logger.info(f"Processed {processed_count} abuse.ch entries through mock Kafka pipeline")
            
            await abuse_ch_service.close()
            return processed_count > 0
        else:
            logger.warning("No abuse.ch data retrieved")
            await abuse_ch_service.close()
            return False
            
    except Exception as e:
        logger.error("Abuse.ch integration test failed", error=str(e))
        return False


async def main():
    """Run all mock Kafka integration tests."""
    logger.info("Starting mock Kafka integration tests...")
    
    tests = [
        ("Mock Kafka Integration", test_mock_kafka_integration),
        ("Abuse.ch Feed Integration", test_abuse_ch_feed_integration),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        logger.info(f"Running test: {test_name}")
        try:
            result = await test_func()
            results.append((test_name, result))
            logger.info(f"Test {test_name}: {'PASSED' if result else 'FAILED'}")
        except Exception as e:
            logger.error(f"Test {test_name} failed with exception", error=str(e))
            results.append((test_name, False))
    
    # Summary
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    logger.info(f"Mock Kafka integration tests completed: {passed}/{total} tests passed")
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
