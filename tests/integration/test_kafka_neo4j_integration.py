"""Integration tests for Kafka consumer and Neo4j integration."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from streaming.kafka_consumer import ThreatIntelligenceProcessor
from database.neo4j.connection import Neo4jConnection


class TestKafkaNeo4jIntegration:
    """Integration tests for Kafka consumer Neo4j operations."""
    
    @pytest.fixture
    def mock_neo4j_connection(self):
        """Mock Neo4j connection."""
        with patch('database.neo4j.connection.Neo4jConnection') as mock_class:
            mock_connection = MagicMock()
            mock_session = MagicMock()
            mock_connection.get_session.return_value.__enter__.return_value = mock_session
            mock_class.return_value = mock_connection
            yield mock_connection
    
    @pytest.fixture
    def processor(self):
        """Create ThreatIntelligenceProcessor instance."""
        return ThreatIntelligenceProcessor()
    
    async def test_ioc_creation_and_relationships(self, processor, mock_neo4j_connection):
        """Test IOC creation with relationships in Neo4j."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"ioc": {"id": "test_ioc_001"}}]
            
            ioc_data = {
                "id": "test_ioc_001",
                "type": "domain",
                "value": "malicious-integration-test.com",
                "category": "malware",
                "confidence": 0.9,
                "source": "integration_test",
                "threat_actors": ["Test APT Group"],
                "campaigns": ["Test Campaign"]
            }
            
            await processor._process_ioc_data(ioc_data)
            
            # Verify IOC creation call
            ioc_calls = [call for call in mock_execute.call_args_list 
                        if "MERGE (ioc:IOC" in call[0][0]]
            assert len(ioc_calls) == 1
            
            # Verify relationship creation calls
            relationship_calls = [call for call in mock_execute.call_args_list 
                               if "USED_BY" in call[0][0] or "SEEN_IN" in call[0][0]]
            assert len(relationship_calls) >= 2  # At least one for each relationship type
    
    async def test_threat_actor_creation_and_relationships(self, processor, mock_neo4j_connection):
        """Test threat actor creation with relationships in Neo4j."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"ta": {"id": "test_actor_001"}}]
            
            actor_data = {
                "id": "test_actor_001",
                "name": "Integration Test APT",
                "aliases": ["INT-APT", "Integration Group"],
                "country": "unknown",
                "motivation": "testing",
                "status": "active",
                "sophistication": "advanced",
                "source": "integration_test",
                "campaigns": ["Integration Campaign"]
            }
            
            await processor._process_threat_actor_data(actor_data)
            
            # Verify threat actor creation call
            actor_calls = [call for call in mock_execute.call_args_list 
                          if "MERGE (ta:ThreatActor" in call[0][0]]
            assert len(actor_calls) == 1
            
            # Verify campaign relationship creation
            campaign_calls = [call for call in mock_execute.call_args_list 
                            if "BELONGS_TO" in call[0][0]]
            assert len(campaign_calls) >= 1
    
    async def test_campaign_creation_and_relationships(self, processor, mock_neo4j_connection):
        """Test campaign creation with relationships in Neo4j."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"c": {"id": "test_campaign_001"}}]
            
            campaign_data = {
                "id": "test_campaign_001",
                "name": "Integration Test Campaign",
                "description": "Campaign for integration testing",
                "status": "active",
                "objectives": ["testing", "validation"],
                "start_date": datetime.utcnow().isoformat(),
                "source": "integration_test",
                "iocs": ["test_ioc_001", "test_ioc_002"]
            }
            
            await processor._process_campaign_data(campaign_data)
            
            # Verify campaign creation call
            campaign_calls = [call for call in mock_execute.call_args_list 
                            if "MERGE (c:Campaign" in call[0][0]]
            assert len(campaign_calls) == 1
            
            # Verify IOC relationship creation
            ioc_calls = [call for call in mock_execute.call_args_list 
                        if "SEEN_IN" in call[0][0]]
            assert len(ioc_calls) >= 2  # One for each IOC
    
    async def test_correlation_processing(self, processor, mock_neo4j_connection):
        """Test correlation data processing in Neo4j."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"a": {"id": "asset_001"}, "ioc": {"id": "ioc_001"}}]
            
            correlation_data = {
                "id": "correlation_001",
                "asset_id": "asset_001",
                "ioc_id": "ioc_001",
                "threat_level": "high",
                "base_risk_score": 0.7
            }
            
            await processor._process_correlation_data(correlation_data)
            
            # Verify exposure relationship creation
            exposure_calls = [call for call in mock_execute.call_args_list 
                            if "EXPOSED_TO" in call[0][0]]
            assert len(exposure_calls) == 1
            
            # Verify risk score update
            risk_calls = [call for call in mock_execute.call_args_list 
                         if "risk_score" in call[0][0]]
            assert len(risk_calls) == 1
    
    async def test_data_consistency_validation(self, processor, mock_neo4j_connection):
        """Test data consistency and validation in Neo4j operations."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"result": "success"}]
            
            # Test with various data quality scenarios
            test_cases = [
                {
                    "id": "consistency_001",
                    "type": "domain",
                    "value": "consistency-test.com",
                    "confidence": 0.95,  # High confidence
                    "category": "malware"
                },
                {
                    "id": "consistency_002", 
                    "type": "ip",
                    "value": "1.2.3.4",
                    "confidence": 0.3,   # Low confidence
                    "category": "suspicious"
                },
                {
                    "id": "consistency_003",
                    "type": "hash",
                    "value": "abc123def456789",
                    "confidence": 1.0,   # Maximum confidence
                    "category": "malware"
                }
            ]
            
            for test_case in test_cases:
                await processor._process_ioc_data(test_case)
            
            # Verify all were processed
            assert mock_execute.call_count >= len(test_cases)
            
            # Verify parameter validation
            for call in mock_execute.call_args_list:
                params = call[0][1]
                assert "id" in params
                assert "type" in params
                assert "value" in params
                assert "confidence" in params
                assert 0 <= params["confidence"] <= 1
    
    async def test_error_handling_and_recovery(self, processor, mock_neo4j_connection):
        """Test error handling and recovery in Neo4j operations."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            # Test Neo4j connection error
            mock_execute.side_effect = Exception("Neo4j connection failed")
            
            processor.logger = MagicMock()
            
            ioc_data = {
                "id": "error_test_001",
                "type": "domain",
                "value": "error-test.com"
            }
            
            # Should handle error gracefully
            await processor._process_ioc_data(ioc_data)
            
            # Verify error was logged
            processor.logger.error.assert_called()
    
    async def test_batch_processing_consistency(self, processor, mock_neo4j_connection):
        """Test batch processing consistency in Neo4j."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"result": "success"}]
            
            # Process batch of related entities
            batch_data = [
                {
                    "id": "batch_actor_001",
                    "type": "threat_actor",
                    "name": "Batch Test Actor"
                },
                {
                    "id": "batch_campaign_001",
                    "type": "campaign", 
                    "name": "Batch Test Campaign",
                    "threat_actors": ["batch_actor_001"]
                },
                {
                    "id": "batch_ioc_001",
                    "type": "domain",
                    "value": "batch-test.com",
                    "threat_actors": ["batch_actor_001"],
                    "campaigns": ["batch_campaign_001"]
                }
            ]
            
            # Process each entity
            for data in batch_data:
                if data["type"] == "threat_actor":
                    await processor._process_threat_actor_data(data)
                elif data["type"] == "campaign":
                    await processor._process_campaign_data(data)
                elif data["type"] == "domain":
                    await processor._process_ioc_data(data)
            
            # Verify all entities were created
            entity_calls = [call for call in mock_execute.call_args_list 
                          if "MERGE" in call[0][0]]
            assert len(entity_calls) >= 3
            
            # Verify relationships were created
            relationship_calls = [call for call in mock_execute.call_args_list 
                               if any(rel in call[0][0] for rel in ["BELONGS_TO", "USED_BY", "SEEN_IN"])]
            assert len(relationship_calls) >= 3
    
    async def test_query_performance_validation(self, processor, mock_neo4j_connection):
        """Test query performance and optimization."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            mock_execute.return_value = [{"result": "success"}]
            
            # Test with larger dataset
            large_dataset = []
            for i in range(50):
                large_dataset.append({
                    "id": f"perf_test_{i:03d}",
                    "type": "domain",
                    "value": f"perf-test-{i:03d}.com",
                    "category": "performance_test",
                    "confidence": 0.5 + (i % 50) / 100
                })
            
            # Process all entities
            start_time = datetime.utcnow()
            for data in large_dataset:
                await processor._process_ioc_data(data)
            end_time = datetime.utcnow()
            
            processing_time = (end_time - start_time).total_seconds()
            
            # Verify all were processed
            assert mock_execute.call_count >= 50
            
            # Performance assertion (should be fast with mocks)
            assert processing_time < 1.0
    
    async def test_transaction_safety(self, processor, mock_neo4j_connection):
        """Test transaction safety and rollback scenarios."""
        with patch('database.neo4j.connection.execute_write_query') as mock_execute:
            # Test partial failure scenario
            call_count = 0
            def side_effect(query, params):
                nonlocal call_count
                call_count += 1
                if call_count == 2:  # Fail on second call
                    raise Exception("Transaction failed")
                return [{"result": "success"}]
            
            mock_execute.side_effect = side_effect
            processor.logger = MagicMock()
            
            # Data that should trigger multiple queries
            complex_data = {
                "id": "transaction_test_001",
                "type": "domain",
                "value": "transaction-test.com",
                "threat_actors": ["Actor1", "Actor2"],
                "campaigns": ["Campaign1", "Campaign2"]
            }
            
            await processor._process_ioc_data(complex_data)
            
            # Verify error was logged
            processor.logger.error.assert_called()
            
            # Verify some operations succeeded before failure
            assert call_count > 1
