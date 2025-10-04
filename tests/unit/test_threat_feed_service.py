"""Unit tests for Threat Feed Service."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from data.ingestion.feed_service import ThreatFeedService


class TestThreatFeedService:
    """Test cases for Threat Feed Service."""
    
    def test_init(self):
        """Test threat feed service initialization."""
        service = ThreatFeedService()
        assert service is not None
        assert hasattr(service, 'logger')
        assert hasattr(service, 'feed_ingestion')
        assert hasattr(service, 'running')
        assert hasattr(service, 'ingestion_interval')
        assert service.ingestion_interval == 3600
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_stream_feed_item_success(self, mock_send_event):
        """Test successful feed item streaming."""
        mock_send_event.return_value = True
        
        service = ThreatFeedService()
        item = {
            "id": "test_item_1",
            "type": "domain",
            "value": "test-malicious.com",
            "source": "test_feed"
        }
        
        result = await service._stream_feed_item(item, "test_feed")
        
        assert result is True
        assert "ingestion_source" in item
        assert "ingestion_timestamp" in item
        assert item["ingestion_source"] == "test_feed"
        mock_send_event.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_stream_feed_item_failure(self, mock_send_event):
        """Test feed item streaming failure."""
        mock_send_event.return_value = False
        
        service = ThreatFeedService()
        item = {
            "id": "test_item_1",
            "type": "domain",
            "value": "test-malicious.com",
            "source": "test_feed"
        }
        
        result = await service._stream_feed_item(item, "test_feed")
        
        assert result is False
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_stream_feed_item_exception(self, mock_send_event):
        """Test feed item streaming with exception."""
        mock_send_event.side_effect = Exception("Kafka error")
        
        service = ThreatFeedService()
        item = {
            "id": "test_item_1",
            "type": "domain",
            "value": "test-malicious.com",
            "source": "test_feed"
        }
        
        result = await service._stream_feed_item(item, "test_feed")
        
        assert result is False
    
    def test_determine_item_type_ioc(self):
        """Test item type determination for IOC."""
        service = ThreatFeedService()
        
        # Test IOC types
        assert service._determine_item_type({"iocs": [{"type": "domain"}]}) == "ioc"
        assert service._determine_item_type({"type": "domain"}) == "ioc"
        assert service._determine_item_type({"type": "ip"}) == "ioc"
        assert service._determine_item_type({"type": "url"}) == "ioc"
        assert service._determine_item_type({"type": "hash"}) == "ioc"
        assert service._determine_item_type({"type": "email"}) == "ioc"
    
    def test_determine_item_type_threat_actor(self):
        """Test item type determination for threat actor."""
        service = ThreatFeedService()
        
        assert service._determine_item_type({"threat_actors": ["APT29"]}) == "threat_actor"
    
    def test_determine_item_type_campaign(self):
        """Test item type determination for campaign."""
        service = ThreatFeedService()
        
        assert service._determine_item_type({"campaigns": ["Test Campaign"]}) == "campaign"
    
    def test_determine_item_type_unknown(self):
        """Test item type determination for unknown."""
        service = ThreatFeedService()
        
        assert service._determine_item_type({}) == "unknown"
        assert service._determine_item_type({"type": "unknown_type"}) == "unknown"
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_ingest_sample_data_success(self, mock_send_event):
        """Test successful sample data ingestion."""
        mock_send_event.return_value = True
        
        service = ThreatFeedService()
        result = await service.ingest_sample_data()
        
        assert result == 3  # Should ingest 3 sample items
        assert mock_send_event.call_count == 3
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_ingest_sample_data_partial_failure(self, mock_send_event):
        """Test sample data ingestion with partial failures."""
        # First two succeed, third fails
        mock_send_event.side_effect = [True, True, False]
        
        service = ThreatFeedService()
        result = await service.ingest_sample_data()
        
        assert result == 2  # Only 2 successful ingestions
        assert mock_send_event.call_count == 3
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_ingest_sample_data_complete_failure(self, mock_send_event):
        """Test sample data ingestion with complete failure."""
        mock_send_event.return_value = False
        
        service = ThreatFeedService()
        result = await service.ingest_sample_data()
        
        assert result == 0  # No successful ingestions
        assert mock_send_event.call_count == 3
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    async def test_ingest_sample_data_exception(self, mock_send_event):
        """Test sample data ingestion with exception."""
        mock_send_event.side_effect = Exception("Kafka error")
        
        service = ThreatFeedService()
        result = await service.ingest_sample_data()
        
        assert result == 0  # No successful ingestions due to exception
        assert mock_send_event.call_count == 3
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    @patch('data.ingestion.feed_service.ThreatFeedIngestion')
    async def test_ingest_and_stream_feeds_success(self, mock_feed_ingestion_class, mock_send_event):
        """Test successful feed ingestion and streaming."""
        mock_send_event.return_value = True
        
        # Mock feed ingestion results
        mock_feed_ingestion = AsyncMock()
        mock_feed_ingestion.ingest_all_feeds.return_value = {
            "abuse_ch": [
                {"id": "ioc_1", "type": "domain", "value": "test1.com"},
                {"id": "ioc_2", "type": "ip", "value": "1.2.3.4"}
            ],
            "otx": [
                {"id": "pulse_1", "name": "Test Pulse", "iocs": [{"type": "url", "value": "http://test.com"}]}
            ],
            "errors": []
        }
        mock_feed_ingestion_class.return_value = mock_feed_ingestion
        
        service = ThreatFeedService()
        await service.ingest_and_stream_feeds()
        
        # Should have sent 3 items to Kafka (2 from abuse_ch + 1 from otx)
        assert mock_send_event.call_count == 3
    
    @pytest.mark.asyncio
    @patch('data.ingestion.feed_service.send_threat_intelligence_event')
    @patch('data.ingestion.feed_service.ThreatFeedIngestion')
    async def test_ingest_and_stream_feeds_with_errors(self, mock_feed_ingestion_class, mock_send_event):
        """Test feed ingestion and streaming with errors."""
        mock_send_event.return_value = True
        
        # Mock feed ingestion with errors
        mock_feed_ingestion = AsyncMock()
        mock_feed_ingestion.ingest_all_feeds.return_value = {
            "abuse_ch": [
                {"id": "ioc_1", "type": "domain", "value": "test1.com"}
            ],
            "otx": [],
            "errors": ["OTX API key not configured"]
        }
        mock_feed_ingestion_class.return_value = mock_feed_ingestion
        
        service = ThreatFeedService()
        await service.ingest_and_stream_feeds()
        
        # Should have sent 1 item to Kafka (only from abuse_ch)
        assert mock_send_event.call_count == 1
