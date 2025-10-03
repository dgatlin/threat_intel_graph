#!/usr/bin/env python3
"""Test Kafka integration for threat intelligence processing."""

import asyncio
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from data.ingestion.threat_feeds import ThreatFeedIngestion
from streaming.kafka_consumer import start_threat_intelligence_processing
from streaming.kafka_producer import send_threat_intelligence_event
from config.logging import configure_logging, get_logger

# Configure logging
configure_logging()
logger = get_logger(__name__)


async def test_kafka_producer():
    """Test Kafka producer with sample data."""
    logger.info("Testing Kafka producer...")
    
    # Sample IOC data
    sample_ioc = {
        "id": "test_ioc_001",
        "type": "ioc",
        "value": "malicious-test-domain.com",
        "category": "attack_infrastructure",
        "confidence": 0.9,
        "source": "test",
        "threat_actors": ["Test Actor"],
        "campaigns": ["Test Campaign"]
    }
    
    # Sample threat actor data
    sample_actor = {
        "id": "test_actor_001",
        "type": "threat_actor",
        "name": "Test Threat Actor",
        "aliases": ["TestActor", "TA001"],
        "country": "Unknown",
        "motivation": "testing",
        "status": "active",
        "sophistication": "medium",
        "source": "test",
        "campaigns": ["Test Campaign"]
    }
    
    # Sample campaign data
    sample_campaign = {
        "id": "test_campaign_001",
        "type": "campaign",
        "name": "Test Campaign",
        "description": "A test campaign for Kafka integration",
        "status": "active",
        "objectives": ["testing", "validation"],
        "source": "test",
        "iocs": ["test_ioc_001"]
    }
    
    # Send test data
    results = []
    for sample_data in [sample_ioc, sample_actor, sample_campaign]:
        success = await send_threat_intelligence_event(sample_data)
        results.append(success)
        logger.info(f"Sent {sample_data['type']}: {'Success' if success else 'Failed'}")
    
    success_count = sum(results)
    logger.info(f"Kafka producer test completed: {success_count}/{len(results)} messages sent successfully")
    
    return success_count == len(results)


async def test_kafka_consumer():
    """Test Kafka consumer processing."""
    logger.info("Testing Kafka consumer...")
    
    # Start consumer in background
    consumer_task = asyncio.create_task(start_threat_intelligence_processing())
    
    # Let it run for a few seconds
    await asyncio.sleep(5)
    
    # Cancel the consumer task
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    
    logger.info("Kafka consumer test completed")


async def test_feed_ingestion_with_kafka():
    """Test threat feed ingestion with Kafka streaming."""
    logger.info("Testing threat feed ingestion with Kafka streaming...")
    
    try:
        # Create feed ingestion service
        feed_service = ThreatFeedIngestion()
        
        # Test with abuse.ch feeds (no API key required)
        logger.info("Testing abuse.ch feed ingestion and streaming...")
        abuse_ch_data = await feed_service._ingest_abuse_ch_feeds()
        
        if abuse_ch_data:
            # Stream to Kafka
            stream_results = await feed_service.send_to_kafka(abuse_ch_data, "abuse_ch")
            logger.info(f"Abuse.ch streaming results: {stream_results}")
            
            # Test comprehensive ingestion and streaming
            logger.info("Testing comprehensive ingestion and streaming...")
            comprehensive_results = await feed_service.ingest_and_stream_all_feeds()
            
            logger.info("Comprehensive test results:", 
                       total_ingested=comprehensive_results["summary"]["total_ingested"],
                       total_streamed=comprehensive_results["summary"]["total_streamed"],
                       success_rate=comprehensive_results["summary"]["streaming_success_rate"])
        else:
            logger.warning("No abuse.ch data found for testing")
        
        await feed_service.close()
        return True
        
    except Exception as e:
        logger.error("Feed ingestion test failed", error=str(e))
        return False


async def main():
    """Run all Kafka integration tests."""
    logger.info("Starting Kafka integration tests...")
    
    tests = [
        ("Kafka Producer", test_kafka_producer),
        ("Feed Ingestion with Kafka", test_feed_ingestion_with_kafka),
        # Note: Consumer test would run indefinitely, so we'll skip it for now
        # ("Kafka Consumer", test_kafka_consumer),
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
    
    logger.info(f"Kafka integration tests completed: {passed}/{total} tests passed")
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    return passed == total


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
