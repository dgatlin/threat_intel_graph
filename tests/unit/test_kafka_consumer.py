"""Unit tests for Kafka consumer functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime
from streaming.kafka_consumer import (
    ThreatIntelligenceConsumer, 
    ThreatIntelligenceProcessor,
    start_threat_intelligence_processing
)


class TestThreatIntelligenceConsumer:
    """Test cases for ThreatIntelligenceConsumer class."""
    
    @patch('streaming.kafka_consumer.KafkaConsumer')
    def test_consumer_initialization(self, mock_kafka_consumer_class):
        """Test consumer initialization."""
        mock_consumer = MagicMock()
        mock_kafka_consumer_class.return_value = mock_consumer
        
        topics = ["test_topic"]
        consumer = ThreatIntelligenceConsumer(topics)
        
        assert consumer.consumer == mock_consumer
        assert consumer.topics == topics
        mock_kafka_consumer_class.assert_called_once()
    
    @patch('streaming.kafka_consumer.KafkaConsumer')
    async def test_consume_messages_success(self, mock_kafka_consumer_class):
        """Test successful message consumption."""
        # Setup mock consumer
        mock_consumer = MagicMock()
        mock_kafka_consumer_class.return_value = mock_consumer
        
        # Mock message data
        mock_message = MagicMock()
        mock_message.topic = "threat_intelligence"
        mock_message.key = b"test_ioc_001"
        mock_message.value = b'{"id": "test_ioc_001", "type": "domain", "value": "test.com"}'
        mock_message.timestamp = (1234567890, 0)
        
        # Mock poll behavior
        mock_consumer.poll.side_effect = [
            {mock_message.topic: [mock_message]},  # First call returns message
            {}  # Second call returns empty (exit condition)
        ]
        
        topics = ["test_topic"]
        consumer = ThreatIntelligenceConsumer(topics)
        processor = MagicMock()
        consumer.processor = processor
        
        # Execute
        await consumer.consume_messages()
        
        # Verify
        assert mock_consumer.poll.call_count >= 1
        processor.process_message.assert_called_once()
    
    @patch('streaming.kafka_consumer.KafkaConsumer')
    async def test_consume_messages_error_handling(self, mock_kafka_consumer_class):
        """Test error handling during message consumption."""
        mock_consumer = MagicMock()
        mock_kafka_consumer_class.return_value = mock_consumer
        
        # Mock poll to raise exception
        mock_consumer.poll.side_effect = Exception("Kafka connection error")
        
        topics = ["test_topic"]
        consumer = ThreatIntelligenceConsumer(topics)
        
        # Should not raise exception, should handle gracefully
        await consumer.consume_messages()
        
        # Verify consumer was closed on error
        mock_consumer.close.assert_called_once()
    
    @patch('streaming.kafka_consumer.KafkaConsumer')
    def test_close_consumer(self, mock_kafka_consumer_class):
        """Test consumer cleanup."""
        mock_consumer = MagicMock()
        mock_kafka_consumer_class.return_value = mock_consumer
        
        topics = ["test_topic"]
        consumer = ThreatIntelligenceConsumer(topics)
        consumer.close()
        
        mock_consumer.close.assert_called_once()


class TestThreatIntelligenceProcessor:
    """Test cases for ThreatIntelligenceProcessor class."""
    
    def test_processor_initialization(self):
        """Test processor initialization."""
        processor = ThreatIntelligenceProcessor()
        
        assert processor.logger is not None
    
    async def test_process_message_valid_ioc(self):
        """Test processing valid IOC message."""
        processor = ThreatIntelligenceProcessor()
        
        # Mock the IOC processing method
        processor._process_ioc_data = AsyncMock()
        
        message = {
            "topic": "threat_intelligence",
            "key": "test_ioc_001",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test",
                "data": {
                    "id": "test_ioc_001",
                    "type": "domain",
                    "value": "malicious-test.com",
                    "category": "malware",
                    "confidence": 0.9
                }
            }
        }
        
        await processor.process_message(message)
        
        processor._process_ioc_data.assert_called_once()
    
    async def test_process_message_valid_threat_actor(self):
        """Test processing valid threat actor message."""
        processor = ThreatIntelligenceProcessor()
        
        # Mock the threat actor processing method
        processor._process_threat_actor_data = AsyncMock()
        
        message = {
            "topic": "threat_intelligence",
            "key": "test_actor_001",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test",
                "data": {
                    "id": "test_actor_001",
                    "type": "threat_actor",
                    "name": "Test APT Group",
                    "aliases": ["APT-TEST"],
                    "motivation": "financial"
                }
            }
        }
        
        await processor.process_message(message)
        
        processor._process_threat_actor_data.assert_called_once()
    
    async def test_process_message_valid_campaign(self):
        """Test processing valid campaign message."""
        processor = ThreatIntelligenceProcessor()
        
        # Mock the campaign processing method
        processor._process_campaign_data = AsyncMock()
        
        message = {
            "topic": "threat_intelligence",
            "key": "test_campaign_001",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test",
                "data": {
                    "id": "test_campaign_001",
                    "type": "campaign",
                    "name": "Test Campaign",
                    "description": "Test campaign for unit testing",
                    "status": "active"
                }
            }
        }
        
        await processor.process_message(message)
        
        processor._process_campaign_data.assert_called_once()
    
    async def test_process_message_invalid_format(self):
        """Test processing message with invalid format."""
        processor = ThreatIntelligenceProcessor()
        
        # Mock logger to verify error logging
        processor.logger = MagicMock()
        
        message = {
            "topic": "threat_intelligence",
            "key": "invalid_message",
            "value": "invalid_json_string"
        }
        
        await processor.process_message(message)
        
        # Verify error was logged
        processor.logger.error.assert_called()
    
    async def test_process_message_missing_data(self):
        """Test processing message with missing data field."""
        processor = ThreatIntelligenceProcessor()
        
        processor.logger = MagicMock()
        
        message = {
            "topic": "threat_intelligence",
            "key": "missing_data",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test"
                # Missing "data" field
            }
        }
        
        await processor.process_message(message)
        
        # Should handle gracefully and log warning
        processor.logger.warning.assert_called()
    
    @patch('database.neo4j.connection.execute_write_query')
    async def test_process_ioc_data_success(self, mock_execute_write_query):
        """Test successful IOC data processing."""
        mock_execute_write_query.return_value = [{"ioc": {"id": "test_ioc_001"}}]
        
        processor = ThreatIntelligenceProcessor()
        processor.logger = MagicMock()
        
        ioc_data = {
            "id": "test_ioc_001",
            "type": "domain",
            "value": "malicious-test.com",
            "category": "malware",
            "confidence": 0.9,
            "source": "test",
            "threat_actors": ["Test Actor"],
            "campaigns": ["Test Campaign"]
        }
        
        await processor._process_ioc_data(ioc_data)
        
        # Verify Neo4j write was called
        assert mock_execute_write_query.call_count >= 1
        processor.logger.info.assert_called()
    
    @patch('database.neo4j.connection.execute_write_query')
    async def test_process_ioc_data_failure(self, mock_execute_write_query):
        """Test IOC data processing failure."""
        mock_execute_write_query.side_effect = Exception("Neo4j error")
        
        processor = ThreatIntelligenceProcessor()
        processor.logger = MagicMock()
        
        ioc_data = {
            "id": "test_ioc_001",
            "type": "domain",
            "value": "malicious-test.com"
        }
        
        await processor._process_ioc_data(ioc_data)
        
        # Verify error was logged
        processor.logger.error.assert_called()
    
    @patch('database.neo4j.connection.execute_write_query')
    async def test_process_threat_actor_data_success(self, mock_execute_write_query):
        """Test successful threat actor data processing."""
        mock_execute_write_query.return_value = [{"ta": {"id": "test_actor_001"}}]
        
        processor = ThreatIntelligenceProcessor()
        processor.logger = MagicMock()
        
        actor_data = {
            "id": "test_actor_001",
            "name": "Test APT Group",
            "aliases": ["APT-TEST"],
            "country": "unknown",
            "motivation": "financial",
            "status": "active",
            "sophistication": "advanced",
            "source": "test",
            "campaigns": ["Test Campaign"]
        }
        
        await processor._process_threat_actor_data(actor_data)
        
        # Verify Neo4j write was called
        assert mock_execute_write_query.call_count >= 1
        processor.logger.info.assert_called()
    
    @patch('database.neo4j.connection.execute_write_query')
    async def test_process_campaign_data_success(self, mock_execute_write_query):
        """Test successful campaign data processing."""
        mock_execute_write_query.return_value = [{"c": {"id": "test_campaign_001"}}]
        
        processor = ThreatIntelligenceProcessor()
        processor.logger = MagicMock()
        
        campaign_data = {
            "id": "test_campaign_001",
            "name": "Test Campaign",
            "description": "Test campaign for unit testing",
            "status": "active",
            "objectives": ["data_theft"],
            "source": "test",
            "iocs": ["test_ioc_001"]
        }
        
        await processor._process_campaign_data(campaign_data)
        
        # Verify Neo4j write was called
        assert mock_execute_write_query.call_count >= 1
        processor.logger.info.assert_called()
    
    @patch('database.neo4j.connection.execute_write_query')
    async def test_process_correlation_data_success(self, mock_execute_write_query):
        """Test successful correlation data processing."""
        mock_execute_write_query.return_value = [{"a": {"id": "asset_001"}, "ioc": {"id": "ioc_001"}}]
        
        processor = ThreatIntelligenceProcessor()
        processor.logger = MagicMock()
        
        correlation_data = {
            "id": "corr_001",
            "asset_id": "asset_001",
            "ioc_id": "ioc_001",
            "threat_level": "high",
            "base_risk_score": 0.5
        }
        
        await processor._process_correlation_data(correlation_data)
        
        # Verify Neo4j writes were called
        assert mock_execute_write_query.call_count >= 1
        processor.logger.info.assert_called()


class TestKafkaConsumerFunctions:
    """Test cases for Kafka consumer convenience functions."""
    
    @patch('streaming.kafka_consumer.get_threat_processor')
    @patch('streaming.kafka_consumer.ThreatIntelligenceConsumer')
    async def test_start_threat_intelligence_processing(self, mock_consumer_class, mock_get_processor):
        """Test start_threat_intelligence_processing function."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer
        mock_consumer.consume_messages = AsyncMock()
        
        mock_processor = MagicMock()
        mock_get_processor.return_value = mock_processor
        
        # Test with timeout
        await start_threat_intelligence_processing(timeout=0.1)
        
        # Verify consumer was created and started
        mock_consumer_class.assert_called_once()
        mock_consumer.consume_messages.assert_called_once_with(timeout=0.1)
        mock_consumer.close.assert_called_once()
