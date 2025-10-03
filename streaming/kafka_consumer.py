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
        # Store IOC in database, update correlations, etc.
        self.logger.info("Processing IOC data", ioc_id=ioc_data.get("id"))
        # TODO: Implement IOC processing logic
    
    async def _process_threat_actor_data(self, actor_data: Dict[str, Any]):
        """Process threat actor data."""
        # Store threat actor in database, update relationships, etc.
        self.logger.info("Processing threat actor data", actor_id=actor_data.get("id"))
        # TODO: Implement threat actor processing logic
    
    async def _process_campaign_data(self, campaign_data: Dict[str, Any]):
        """Process campaign data."""
        # Store campaign in database, update timeline, etc.
        self.logger.info("Processing campaign data", campaign_id=campaign_data.get("id"))
        # TODO: Implement campaign processing logic
    
    async def _process_correlation_data(self, correlation_data: Dict[str, Any]):
        """Process correlation data."""
        # Update asset risk scores, trigger alerts, etc.
        self.logger.info("Processing correlation data", correlation_id=correlation_data.get("id"))
        # TODO: Implement correlation processing logic


# Global processor instance
threat_processor = ThreatIntelligenceProcessor()


async def start_threat_intelligence_processing():
    """Start threat intelligence processing from Kafka."""
    await threat_processor.start_processing()

