"""Integration tests for Kafka pipeline."""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime
import asyncio
from streaming.kafka_producer import ThreatIntelligenceProducer
from streaming.kafka_consumer import ThreatIntelligenceProcessor
from data.ingestion.threat_feeds import ThreatFeedIngestion


class TestKafkaPipelineIntegration:
    """Integration tests for Kafka producer-consumer pipeline."""
    
    @pytest.fixture
    def mock_kafka_producer(self):
        """Mock Kafka producer."""
        with patch('streaming.kafka_producer.KafkaProducer') as mock_class:
            mock_producer = MagicMock()
            mock_future = MagicMock()
            mock_record_metadata = MagicMock()
            mock_record_metadata.partition = 0
            mock_record_metadata.offset = 123
            mock_future.get.return_value = mock_record_metadata
            mock_producer.send.return_value = mock_future
            mock_class.return_value = mock_producer
            yield mock_producer
    
    @pytest.fixture
    def mock_kafka_consumer(self):
        """Mock Kafka consumer."""
        with patch('streaming.kafka_consumer.KafkaConsumer') as mock_class:
            mock_consumer = MagicMock()
            mock_class.return_value = mock_consumer
            yield mock_consumer
    
    @pytest.fixture
    def mock_neo4j_execute(self):
        """Mock Neo4j execute_write_query function."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"id": "test_result"}]
            yield mock_execute
    
    async def test_end_to_end_pipeline_success(self, mock_kafka_producer, mock_kafka_consumer, mock_neo4j_execute):
        """Test complete end-to-end pipeline from producer to Neo4j."""
        # Setup producer
        producer = ThreatIntelligenceProducer()
        
        # Setup processor with mocked Neo4j
        processor = ThreatIntelligenceProcessor()
        
        # Test data
        threat_data = {
            "id": "integration_test_001",
            "type": "domain",
            "value": "integration-test-malicious.com",
            "category": "malware",
            "confidence": 0.9,
            "source": "integration_test"
        }
        
        # Step 1: Producer sends message
        producer_result = await producer.send_threat_intelligence(threat_data)
        assert producer_result is True
        
        # Step 2: Simulate message consumption and processing
        message = {
            "topic": "threat_intelligence",
            "key": "integration_test_001",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "integration_test",
                "data": threat_data
            }
        }
        
        await processor.process_message(message)
        
        # Step 3: Verify Neo4j write was called
        assert mock_neo4j_execute.call_count >= 1
        
        # Verify the query structure
        call_args = mock_neo4j_execute.call_args_list[0]
        query = call_args[0][0]
        params = call_args[0][1]
        
        assert "MERGE (ioc:IOC" in query
        assert params["id"] == "integration_test_001"
        assert params["type"] == "domain"
        assert params["value"] == "integration-test-malicious.com"
    
    async def test_batch_processing_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test batch processing through the pipeline."""
        producer = ThreatIntelligenceProducer()
        processor = ThreatIntelligenceProcessor()
        
        # Batch of threat data
        threat_data_list = [
            {
                "id": "batch_001",
                "type": "ip",
                "value": "1.2.3.4",
                "category": "malicious_ip",
                "confidence": 0.8
            },
            {
                "id": "batch_002",
                "type": "domain",
                "value": "malicious-batch.com",
                "category": "malware",
                "confidence": 0.9
            },
            {
                "id": "batch_003",
                "type": "hash",
                "value": "abc123def456",
                "category": "malware",
                "confidence": 0.95
            }
        ]
        
        # Send batch
        results = await producer.send_batch_threat_data(threat_data_list)
        assert results["success"] == 3
        assert results["failed"] == 0
        
        # Process each message
        for threat_data in threat_data_list:
            message = {
                "topic": "threat_intelligence",
                "key": threat_data["id"],
                "value": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "batch_test",
                    "data": threat_data
                }
            }
            await processor.process_message(message)
        
        # Verify all were processed in Neo4j
        assert mock_neo4j_execute.call_count >= 3
    
    async def test_correlation_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test correlation data processing pipeline."""
        producer = ThreatIntelligenceProducer()
        processor = ThreatIntelligenceProcessor()
        
        # Correlation data
        correlation_data = {
            "asset_id": "asset_integration_001",
            "ioc_id": "ioc_integration_001",
            "threat_level": "high",
            "base_risk_score": 0.6
        }
        
        # Send correlation
        result = await producer.send_ioc_correlation(correlation_data)
        assert result is True
        
        # Process correlation
        message = {
            "topic": "ioc_correlation",
            "key": f"{correlation_data['asset_id']}_{correlation_data['ioc_id']}",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "correlation_test",
                "data": correlation_data
            }
        }
        
        await processor.process_message(message)
        
        # Verify correlation processing
        assert mock_neo4j_execute.call_count >= 1
        
        # Check for exposure relationship creation
        exposure_calls = [call for call in mock_neo4j_execute.call_args_list 
                         if "EXPOSED_TO" in call[0][0]]
        assert len(exposure_calls) > 0
    
    async def test_error_handling_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test error handling throughout the pipeline."""
        producer = ThreatIntelligenceProducer()
        processor = ThreatIntelligenceProcessor()
        
        # Test with invalid data
        invalid_data = {
            "id": "error_test_001",
            "type": "invalid_type",
            "value": "",  # Empty value
            "confidence": -1  # Invalid confidence
        }
        
        # Producer should still send (validation happens at consumer)
        result = await producer.send_threat_intelligence(invalid_data)
        assert result is True
        
        # Consumer should handle gracefully
        message = {
            "topic": "threat_intelligence",
            "key": "error_test_001",
            "value": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "error_test",
                "data": invalid_data
            }
        }
        
        # Should not raise exception
        await processor.process_message(message)
        
        # Neo4j might still be called but with default values
        assert mock_neo4j_execute.call_count >= 1
    
    async def test_performance_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test pipeline performance with multiple messages."""
        producer = ThreatIntelligenceProducer()
        processor = ThreatIntelligenceProcessor()
        
        # Generate larger batch
        threat_data_list = []
        for i in range(100):
            threat_data_list.append({
                "id": f"perf_test_{i:03d}",
                "type": "domain",
                "value": f"perf-test-{i:03d}.com",
                "category": "performance_test",
                "confidence": 0.5 + (i % 50) / 100
            })
        
        # Measure batch sending time
        start_time = datetime.utcnow()
        results = await producer.send_batch_threat_data(threat_data_list)
        send_time = (datetime.utcnow() - start_time).total_seconds()
        
        assert results["success"] == 100
        assert results["failed"] == 0
        
        # Measure processing time
        start_time = datetime.utcnow()
        
        # Process all messages concurrently
        tasks = []
        for threat_data in threat_data_list:
            message = {
                "topic": "threat_intelligence",
                "key": threat_data["id"],
                "value": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "performance_test",
                    "data": threat_data
                }
            }
            tasks.append(processor.process_message(message))
        
        await asyncio.gather(*tasks)
        process_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Verify all were processed
        assert mock_neo4j_execute.call_count >= 100
        
        # Performance assertions (should complete quickly with mocks)
        assert send_time < 1.0  # Sending should be fast
        assert process_time < 2.0  # Processing should be fast
    
    async def test_feed_integration_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test integration with threat feed ingestion."""
        # Mock feed ingestion
        with patch('data.ingestion.threat_feeds.ThreatFeedIngestion.ingest_all_feeds') as mock_ingest:
            mock_ingest.return_value = {
                "abuse_ch": [
                    {
                        "id": "abuse_integration_001",
                        "type": "domain",
                        "value": "abuse-integration-test.com",
                        "source": "abuse_ch_feodo",
                        "confidence": 0.9
                    }
                ],
                "otx": [
                    {
                        "id": "otx_integration_001",
                        "name": "OTX Integration Test",
                        "iocs": ["otx_ioc_001"]
                    }
                ],
                "errors": []
            }
            
            # Mock HTTP client
            with patch('data.ingestion.threat_feeds.httpx.AsyncClient'):
                feed_service = ThreatFeedIngestion()
                
                # Test comprehensive ingestion and streaming
                results = await feed_service.ingest_and_stream_all_feeds()
                
                assert "ingestion" in results
                assert "streaming" in results
                assert "summary" in results
                
                # Verify streaming results
                streaming = results["streaming"]
                assert "abuse_ch" in streaming
                assert "otx" in streaming
                
                # Verify summary
                summary = results["summary"]
                assert summary["total_ingested"] >= 2
                assert summary["streaming_success_rate"] > 0
    
    async def test_message_ordering_pipeline(self, mock_kafka_producer, mock_neo4j_execute):
        """Test message ordering and consistency."""
        producer = ThreatIntelligenceProducer()
        processor = ThreatIntelligenceProcessor()
        
        # Create related messages that should be processed in order
        actor_data = {
            "id": "ordering_actor_001",
            "name": "Ordering Test Actor",
            "type": "threat_actor"
        }
        
        campaign_data = {
            "id": "ordering_campaign_001",
            "name": "Ordering Test Campaign",
            "type": "campaign",
            "threat_actors": ["ordering_actor_001"]
        }
        
        ioc_data = {
            "id": "ordering_ioc_001",
            "type": "domain",
            "value": "ordering-test.com",
            "threat_actors": ["ordering_actor_001"],
            "campaigns": ["ordering_campaign_001"]
        }
        
        # Send messages in sequence
        await producer.send_threat_intelligence(actor_data)
        await producer.send_threat_intelligence(campaign_data)
        await producer.send_threat_intelligence(ioc_data)
        
        # Process messages in the same order
        messages = [
            {
                "topic": "threat_intelligence",
                "key": "ordering_actor_001",
                "value": {"timestamp": datetime.utcnow().isoformat(), "data": actor_data}
            },
            {
                "topic": "threat_intelligence",
                "key": "ordering_campaign_001", 
                "value": {"timestamp": datetime.utcnow().isoformat(), "data": campaign_data}
            },
            {
                "topic": "threat_intelligence",
                "key": "ordering_ioc_001",
                "value": {"timestamp": datetime.utcnow().isoformat(), "data": ioc_data}
            }
        ]
        
        for message in messages:
            await processor.process_message(message)
        
        # Verify all entities were created
        assert mock_neo4j_execute.call_count >= 3
        
        # Verify relationship creation calls
        relationship_calls = [call for call in mock_neo4j_execute.call_args_list 
                            if "BELONGS_TO" in call[0][0] or "USED_BY" in call[0][0] or "SEEN_IN" in call[0][0]]
        assert len(relationship_calls) > 0
