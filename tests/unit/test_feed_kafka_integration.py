"""Unit tests for feed ingestion and Kafka integration."""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime
from data.ingestion.threat_feeds import ThreatFeedIngestion
from data.ingestion.abuse_ch_feeds import AbuseChFeedIngestion
from data.ingestion.otx_feeds import OTXFeedIngestion


class TestThreatFeedIngestionKafkaIntegration:
    """Test cases for ThreatFeedIngestion Kafka integration."""
    
    @pytest.fixture
    def mock_kafka_send(self):
        """Mock the Kafka send function."""
        with patch('data.ingestion.threat_feeds.send_threat_intelligence_event') as mock_send:
            mock_send.return_value = True
            yield mock_send
    
    @pytest.fixture
    def threat_feed_service(self):
        """Create ThreatFeedIngestion service with mocked HTTP client."""
        with patch('data.ingestion.threat_feeds.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            service = ThreatFeedIngestion()
            service.http_client = mock_client
            return service
    
    async def test_send_to_kafka_success(self, threat_feed_service, mock_kafka_send):
        """Test successful sending of threat data to Kafka."""
        threat_data = [
            {
                "id": "test_ioc_001",
                "type": "domain",
                "value": "malicious-test.com",
                "category": "malware",
                "confidence": 0.9,
                "source": "test"
            },
            {
                "id": "test_actor_001",
                "name": "Test APT Group",
                "aliases": ["APT-TEST"],
                "type": "threat_actor"
            }
        ]
        
        results = await threat_feed_service.send_to_kafka(threat_data, "test_source")
        
        assert results["success"] == 2
        assert results["failed"] == 0
        assert mock_kafka_send.call_count == 2
    
    async def test_send_to_kafka_failure_handling(self, threat_feed_service):
        """Test Kafka sending failure handling."""
        with patch('data.ingestion.threat_feeds.send_threat_intelligence_event') as mock_send:
            mock_send.side_effect = Exception("Kafka connection error")
            
            threat_data = [
                {"id": "test_ioc_001", "type": "domain", "value": "test.com"}
            ]
            
            results = await threat_feed_service.send_to_kafka(threat_data, "test_source")
            
            assert results["success"] == 0
            assert results["failed"] == 1
    
    async def test_send_to_kafka_message_type_detection(self, threat_feed_service, mock_kafka_send):
        """Test automatic message type detection."""
        threat_data = [
            # IOC message
            {
                "id": "test_ioc_001",
                "type": "ip",
                "value": "1.2.3.4"
            },
            # Campaign message
            {
                "id": "test_campaign_001",
                "name": "Test Campaign",
                "iocs": ["test_ioc_001"]
            },
            # Threat actor message
            {
                "id": "test_actor_001",
                "name": "Test Actor",
                "threat_actors": ["Test Actor"],
                "iocs": ["test_ioc_001"]
            }
        ]
        
        await threat_feed_service.send_to_kafka(threat_data, "test_source")
        
        # Verify correct message types were detected
        calls = mock_kafka_send.call_args_list
        assert len(calls) == 3
        
        # Check message types
        assert calls[0][0][0]["type"] == "ioc"
        assert calls[1][0][0]["type"] == "campaign"
        assert calls[2][0][0]["type"] == "threat_actor"
    
    async def test_ingest_and_stream_all_feeds(self, threat_feed_service, mock_kafka_send):
        """Test comprehensive ingestion and streaming."""
        # Mock the ingest_all_feeds method
        threat_feed_service.ingest_all_feeds = AsyncMock(return_value={
            "misp": [
                {"id": "misp_001", "type": "domain", "value": "misp-test.com"}
            ],
            "otx": [
                {"id": "otx_001", "name": "OTX Pulse", "iocs": ["otx_ioc_001"]}
            ],
            "abuse_ch": [
                {"id": "abuse_001", "type": "url", "value": "http://abuse-test.com"}
            ],
            "errors": []
        })
        
        results = await threat_feed_service.ingest_and_stream_all_feeds()
        
        # Verify structure
        assert "ingestion" in results
        assert "streaming" in results
        assert "summary" in results
        
        # Verify streaming results
        streaming_results = results["streaming"]
        assert "misp" in streaming_results
        assert "otx" in streaming_results
        assert "abuse_ch" in streaming_results
        
        # Verify summary
        summary = results["summary"]
        assert summary["total_ingested"] == 3
        assert summary["total_streamed"] == 3
        assert summary["streaming_success_rate"] == 1.0


class TestAbuseChFeedKafkaIntegration:
    """Test cases for AbuseChFeedIngestion Kafka integration."""
    
    @pytest.fixture
    def abuse_ch_service(self):
        """Create AbuseChFeedIngestion service with mocked HTTP client."""
        with patch('data.ingestion.abuse_ch_feeds.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            service = AbuseChFeedIngestion()
            service.http_client = mock_client
            return service
    
    async def test_fetch_feodo_tracker_success(self, abuse_ch_service):
        """Test successful Feodo Tracker data fetching."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.text = "1.2.3.4\n5.6.7.8\n9.10.11.12"
        mock_response.raise_for_status = MagicMock()
        abuse_ch_service.http_client.get.return_value = mock_response
        
        result = await abuse_ch_service.fetch_feodo_tracker()
        
        assert len(result) == 3
        assert result[0]["type"] == "ip_address"
        assert result[0]["value"] == "1.2.3.4"
        assert result[0]["source"] == "abuse_ch_feodo"
        assert result[0]["category"] == "botnet_c2"
    
    async def test_fetch_sslbl_success(self, abuse_ch_service):
        """Test successful SSL Blacklist data fetching."""
        # Mock HTTP response with CSV data
        mock_response = MagicMock()
        mock_response.text = "first_seen,threat,listing_ip,listing_port,listing_reason\n2023-01-01 00:00:00,Malware,1.2.3.4,443,Malware distribution"
        mock_response.raise_for_status = MagicMock()
        abuse_ch_service.http_client.get.return_value = mock_response
        
        result = await abuse_ch_service.fetch_sslbl()
        
        assert len(result) == 1
        assert result[0]["type"] == "ssl_certificate"
        assert result[0]["source"] == "abuse_ch_sslbl"
    
    async def test_fetch_urlhaus_success(self, abuse_ch_service):
        """Test successful URLhaus data fetching."""
        # Mock HTTP response with CSV data
        mock_response = MagicMock()
        mock_response.text = "id,dateadded,url,url_status,threat,malware,tags\n123456,2023-01-01 00:00:00,http://malicious-test.com,online,malware_download,zeus,malware"
        mock_response.raise_for_status = MagicMock()
        abuse_ch_service.http_client.get.return_value = mock_response
        
        result = await abuse_ch_service.fetch_urlhaus()
        
        assert len(result) == 1
        assert result[0]["type"] == "url"
        assert result[0]["value"] == "http://malicious-test.com"
        assert result[0]["source"] == "abuse_ch_urlhaus"
    
    async def test_ingest_all_feeds_integration(self, abuse_ch_service):
        """Test complete feed ingestion integration."""
        # Mock all fetch methods
        abuse_ch_service.fetch_feodo_tracker = AsyncMock(return_value=[
            {"id": "feodo_001", "type": "ip_address", "value": "1.2.3.4"}
        ])
        abuse_ch_service.fetch_sslbl = AsyncMock(return_value=[
            {"id": "sslbl_001", "type": "ssl_certificate", "value": "malicious-cert.com"}
        ])
        abuse_ch_service.fetch_urlhaus = AsyncMock(return_value=[
            {"id": "urlhaus_001", "type": "url", "value": "http://malicious-test.com"}
        ])
        
        result = await abuse_ch_service.ingest_all_feeds()
        
        assert "feodo" in result
        assert "sslbl" in result
        assert "urlhaus" in result
        assert result["total_iocs"] == 3
        assert result["feeds_processed"] == 3


class TestOTXFeedKafkaIntegration:
    """Test cases for OTXFeedIngestion Kafka integration."""
    
    @pytest.fixture
    def otx_service(self):
        """Create OTXFeedIngestion service with mocked HTTP client."""
        with patch('data.ingestion.otx_feeds.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            service = OTXFeedIngestion()
            service.http_client = mock_client
            return service
    
    async def test_fetch_pulses_success(self, otx_service):
        """Test successful OTX pulses fetching."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {
                    "id": "pulse_001",
                    "name": "Test Pulse",
                    "description": "Test pulse description",
                    "author": {"username": "test_user"},
                    "created": "2023-01-01T00:00:00Z",
                    "modified": "2023-01-01T00:00:00Z",
                    "tags": ["malware", "test"],
                    "indicators": [
                        {
                            "type": "domain",
                            "indicator": "test-malicious.com",
                            "created": "2023-01-01T00:00:00Z"
                        }
                    ]
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        otx_service.http_client.get.return_value = mock_response
        
        result = await otx_service.fetch_pulses()
        
        assert len(result) == 1
        assert result[0]["id"] == "pulse_001"
        assert result[0]["name"] == "Test Pulse"
        assert len(result[0]["iocs"]) == 1
        assert result[0]["iocs"][0]["type"] == "domain"
        assert result[0]["iocs"][0]["value"] == "test-malicious.com"
    
    async def test_fetch_indicators_success(self, otx_service):
        """Test successful OTX indicators fetching."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {
                    "id": "indicator_001",
                    "type": "domain",
                    "indicator": "malicious-test.com",
                    "created": "2023-01-01T00:00:00Z",
                    "threat_score": 85,
                    "pulse_count": 3
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        otx_service.http_client.get.return_value = mock_response
        
        result = await otx_service.fetch_indicators()
        
        assert len(result) == 1
        assert result[0]["id"] == "indicator_001"
        assert result[0]["type"] == "domain"
        assert result[0]["value"] == "malicious-test.com"
        assert result[0]["confidence"] == 0.85  # threat_score / 100
    
    async def test_ingest_recent_threats_integration(self, otx_service):
        """Test complete OTX threat ingestion integration."""
        # Mock fetch methods
        otx_service.fetch_pulses = AsyncMock(return_value=[
            {"id": "pulse_001", "name": "Test Pulse", "iocs": []}
        ])
        otx_service.fetch_indicators = AsyncMock(return_value=[
            {"id": "indicator_001", "type": "domain", "value": "test.com"}
        ])
        
        result = await otx_service.ingest_recent_threats(hours_back=24)
        
        assert "pulses" in result
        assert "indicators" in result
        assert len(result["pulses"]) == 1
        assert len(result["indicators"]) == 1
