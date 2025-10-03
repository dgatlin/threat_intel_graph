"""Unit tests for Kafka producer functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from streaming.kafka_producer import ThreatIntelligenceProducer, send_threat_intelligence_event


class TestThreatIntelligenceProducer:
    """Test cases for ThreatIntelligenceProducer class."""
    
    @patch('streaming.kafka_producer.KafkaProducer')
    def test_producer_initialization(self, mock_kafka_producer_class):
        """Test producer initialization."""
        mock_producer = MagicMock()
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        
        assert producer.producer == mock_producer
        mock_kafka_producer_class.assert_called_once()
    
    @patch('streaming.kafka_producer.KafkaProducer')
    async def test_send_threat_intelligence_success(self, mock_kafka_producer_class):
        """Test successful threat intelligence message sending."""
        # Setup mock
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_record_metadata = MagicMock()
        mock_record_metadata.partition = 0
        mock_record_metadata.offset = 123
        mock_future.get.return_value = mock_record_metadata
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        
        # Test data
        threat_data = {
            "id": "test_ioc_001",
            "type": "domain",
            "value": "malicious-test.com",
            "confidence": 0.9
        }
        
        # Execute
        result = await producer.send_threat_intelligence(threat_data)
        
        # Verify
        assert result is True
        mock_producer.send.assert_called_once()
        
        # Check the message format
        call_args = mock_producer.send.call_args
        topic = call_args[0][0]
        value = call_args[1]['value']
        key = call_args[1]['key']
        
        assert topic == "threat_intelligence"
        assert key == "test_ioc_001"
        assert "timestamp" in value
        assert "source" in value
        assert value["data"] == threat_data
    
    @patch('streaming.kafka_producer.KafkaProducer')
    async def test_send_threat_intelligence_failure(self, mock_kafka_producer_class):
        """Test threat intelligence message sending failure."""
        # Setup mock to raise exception
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.side_effect = Exception("Kafka error")
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        
        threat_data = {"id": "test_ioc_001", "type": "domain", "value": "test.com"}
        
        result = await producer.send_threat_intelligence(threat_data)
        
        assert result is False
    
    @patch('streaming.kafka_producer.KafkaProducer')
    async def test_send_ioc_correlation(self, mock_kafka_producer_class):
        """Test IOC correlation message sending."""
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_record_metadata = MagicMock()
        mock_record_metadata.partition = 0
        mock_record_metadata.offset = 456
        mock_future.get.return_value = mock_record_metadata
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        
        correlation_data = {
            "asset_id": "asset_001",
            "ioc_id": "ioc_001",
            "correlation_type": "exposure"
        }
        
        result = await producer.send_ioc_correlation(correlation_data)
        
        assert result is True
        
        # Verify it was sent to the correct topic
        call_args = mock_producer.send.call_args
        topic = call_args[0][0]
        assert topic == "ioc_correlation"
    
    @patch('streaming.kafka_producer.KafkaProducer')
    async def test_send_batch_threat_data(self, mock_kafka_producer_class):
        """Test batch threat data sending."""
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_record_metadata = MagicMock()
        mock_future.get.return_value = mock_record_metadata
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        
        threat_data_list = [
            {"id": "test_001", "type": "domain", "value": "test1.com"},
            {"id": "test_002", "type": "ip", "value": "1.2.3.4"},
            {"id": "test_003", "type": "hash", "value": "abc123"}
        ]
        
        results = await producer.send_batch_threat_data(threat_data_list)
        
        assert results["success"] == 3
        assert results["failed"] == 0
        assert mock_producer.send.call_count == 3
    
    @patch('streaming.kafka_producer.KafkaProducer')
    def test_close_producer(self, mock_kafka_producer_class):
        """Test producer cleanup."""
        mock_producer = MagicMock()
        mock_kafka_producer_class.return_value = mock_producer
        
        producer = ThreatIntelligenceProducer()
        producer.close()
        
        mock_producer.flush.assert_called_once()
        mock_producer.close.assert_called_once()


class TestKafkaProducerFunctions:
    """Test cases for Kafka producer convenience functions."""
    
    @patch('streaming.kafka_producer.get_threat_producer')
    async def test_send_threat_intelligence_event(self, mock_get_producer):
        """Test send_threat_intelligence_event function."""
        mock_producer = MagicMock()
        mock_producer.send_threat_intelligence.return_value = True
        mock_get_producer.return_value = mock_producer
        
        threat_data = {"id": "test_001", "type": "domain", "value": "test.com"}
        
        result = await send_threat_intelligence_event(threat_data)
        
        assert result is True
        mock_producer.send_threat_intelligence.assert_called_once_with(threat_data, None)
    
    @patch('streaming.kafka_producer.get_threat_producer')
    async def test_send_threat_intelligence_event_with_topic(self, mock_get_producer):
        """Test send_threat_intelligence_event function with custom topic."""
        mock_producer = MagicMock()
        mock_producer.send_threat_intelligence.return_value = True
        mock_get_producer.return_value = mock_producer
        
        threat_data = {"id": "test_001", "type": "domain", "value": "test.com"}
        topic = "custom_topic"
        
        result = await send_threat_intelligence_event(threat_data, topic)
        
        assert result is True
        mock_producer.send_threat_intelligence.assert_called_once_with(threat_data, topic)
