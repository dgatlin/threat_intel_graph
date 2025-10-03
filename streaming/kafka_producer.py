"""Kafka producer for threat intelligence streaming."""

import json
import asyncio
from typing import Dict, Any, List
from datetime import datetime
import structlog
from kafka import KafkaProducer
from kafka.errors import KafkaError
from config.settings import settings

logger = structlog.get_logger(__name__)


class ThreatIntelligenceProducer:
    """Kafka producer for streaming threat intelligence data."""
    
    def __init__(self):
        self.logger = logger.bind(service="kafka_producer")
        self.producer = None
        self._connect()
    
    def _connect(self):
        """Connect to Kafka cluster."""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=settings.kafka_brokers.split(','),
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',  # Wait for all replicas to acknowledge
                retries=3,
                retry_backoff_ms=100,
                request_timeout_ms=30000
            )
            self.logger.info("Connected to Kafka cluster", brokers=settings.kafka_brokers)
        except Exception as e:
            self.logger.error("Failed to connect to Kafka", error=str(e))
            raise
    
    async def send_threat_intelligence(self, threat_data: Dict[str, Any], topic: str = None) -> bool:
        """Send threat intelligence data to Kafka topic."""
        if not self.producer:
            self._connect()
        
        topic = topic or settings.kafka_topic_threat_intel
        
        try:
            # Add metadata
            message = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "threat_intelligence_api",
                "data": threat_data
            }
            
            # Send message
            future = self.producer.send(
                topic,
                value=message,
                key=threat_data.get("id", "unknown")
            )
            
            # Wait for confirmation
            record_metadata = future.get(timeout=10)
            
            self.logger.info(
                "Threat intelligence sent to Kafka",
                topic=topic,
                partition=record_metadata.partition,
                offset=record_metadata.offset
            )
            
            return True
            
        except KafkaError as e:
            self.logger.error("Failed to send threat intelligence to Kafka", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Unexpected error sending to Kafka", error=str(e))
            return False
    
    async def send_ioc_correlation(self, correlation_data: Dict[str, Any]) -> bool:
        """Send IOC correlation data to Kafka topic."""
        return await self.send_threat_intelligence(
            correlation_data, 
            settings.kafka_topic_ioc_correlation
        )
    
    async def send_batch_threat_data(self, threat_data_list: List[Dict[str, Any]]) -> Dict[str, int]:
        """Send batch of threat intelligence data."""
        results = {"success": 0, "failed": 0}
        
        for threat_data in threat_data_list:
            success = await self.send_threat_intelligence(threat_data)
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
        
        self.logger.info("Batch threat data sent", results=results)
        return results
    
    def close(self):
        """Close Kafka producer."""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            self.logger.info("Kafka producer closed")


# Global producer instance (lazy initialization)
threat_producer = None

def get_threat_producer():
    """Get or create the global threat producer instance."""
    global threat_producer
    if threat_producer is None:
        threat_producer = ThreatIntelligenceProducer()
    return threat_producer


async def send_threat_intelligence_event(threat_data: Dict[str, Any], topic: str = None) -> bool:
    """Convenience function to send threat intelligence event."""
    producer = get_threat_producer()
    return await producer.send_threat_intelligence(threat_data, topic)


async def send_ioc_correlation_event(correlation_data: Dict[str, Any]) -> bool:
    """Convenience function to send IOC correlation event."""
    producer = get_threat_producer()
    return await producer.send_ioc_correlation(correlation_data)