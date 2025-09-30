"""Unit tests for Threat Feed Ingestion."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from data.ingestion.otx_feeds import OTXFeedIngestion
from data.ingestion.abuse_ch_feeds import AbuseChFeedIngestion


class TestOTXFeedIngestion:
    """Test cases for OTX Feed Ingestion."""
    
    def test_init(self):
        """Test OTX feed ingestion initialization."""
        otx = OTXFeedIngestion()
        assert otx is not None
        assert hasattr(otx, 'logger')
        assert hasattr(otx, 'http_client')
    
    @pytest.mark.asyncio
    @patch('data.ingestion.otx_feeds.settings')
    async def test_ingest_recent_threats_no_api_key(self, mock_settings):
        """Test ingestion with no API key configured."""
        mock_settings.otx_api_key = None
        
        otx = OTXFeedIngestion()
        result = await otx.ingest_recent_threats(hours_back=24)
        
        assert result["pulses"] == []
        assert result["indicators"] == []
    
    @pytest.mark.asyncio
    @patch('data.ingestion.otx_feeds.settings')
    @patch('data.ingestion.otx_feeds.httpx.AsyncClient')
    async def test_ingest_recent_threats_success(self, mock_httpx, mock_settings, sample_otx_pulse):
        """Test successful threat ingestion from OTX."""
        mock_settings.otx_api_key = "test_api_key"
        
        # Mock HTTP responses
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"results": [sample_otx_pulse]}
        mock_client.get.return_value = mock_response
        mock_httpx.return_value = mock_client
        
        otx = OTXFeedIngestion()
        otx.http_client = mock_client
        
        result = await otx.ingest_recent_threats(hours_back=168)
        
        assert "pulses" in result
        assert "indicators" in result
    
    @pytest.mark.asyncio
    @patch('data.ingestion.otx_feeds.settings')
    async def test_ingest_recent_threats_http_error(self, mock_settings):
        """Test ingestion with HTTP error."""
        mock_settings.otx_api_key = "test_api_key"
        
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("HTTP Error")
        
        otx = OTXFeedIngestion()
        otx.http_client = mock_client
        
        result = await otx.ingest_recent_threats(hours_back=24)
        
        assert result["pulses"] == []
        assert result["indicators"] == []
    
    @pytest.mark.asyncio
    async def test_close(self):
        """Test closing HTTP client."""
        otx = OTXFeedIngestion()
        otx.http_client = AsyncMock()
        
        await otx.close()
        otx.http_client.aclose.assert_called_once()


class TestAbuseChFeedIngestion:
    """Test cases for Abuse.ch Feed Ingestion."""
    
    def test_init(self):
        """Test Abuse.ch feed ingestion initialization."""
        abuse_ch = AbuseChFeedIngestion()
        assert abuse_ch is not None
        assert hasattr(abuse_ch, 'logger')
        assert hasattr(abuse_ch, 'http_client')
        assert hasattr(abuse_ch, 'feeds')
        assert "feodo" in abuse_ch.feeds
        assert "sslbl" in abuse_ch.feeds
        assert "urlhaus" in abuse_ch.feeds
    
    @pytest.mark.asyncio
    @patch('data.ingestion.abuse_ch_feeds.httpx.AsyncClient')
    async def test_fetch_feodo_tracker_success(self, mock_httpx):
        """Test successful Feodo Tracker fetch."""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.text = "# Comment\n192.168.1.1\n10.0.0.1"
        mock_client.get.return_value = mock_response
        mock_httpx.return_value = mock_client
        
        abuse_ch = AbuseChFeedIngestion()
        abuse_ch.http_client = mock_client
        
        result = await abuse_ch.fetch_feodo_tracker()
        
        assert len(result) == 2
        assert result[0]["type"] == "ip_address"
        assert result[0]["value"] == "192.168.1.1"
    
    @pytest.mark.asyncio
    @patch('data.ingestion.abuse_ch_feeds.httpx.AsyncClient')
    async def test_fetch_feodo_tracker_error(self, mock_httpx):
        """Test Feodo Tracker fetch with error."""
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("HTTP Error")
        mock_httpx.return_value = mock_client
        
        abuse_ch = AbuseChFeedIngestion()
        abuse_ch.http_client = mock_client
        
        result = await abuse_ch.fetch_feodo_tracker()
        
        assert result == []
    
    @pytest.mark.asyncio
    @patch('data.ingestion.abuse_ch_feeds.httpx.AsyncClient')
    async def test_fetch_urlhaus_success(self, mock_httpx):
        """Test successful URLhaus fetch."""
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.text = '"id","date","url"\n"1","2025-01-01","http://malicious.com"'
        mock_client.get.return_value = mock_response
        mock_httpx.return_value = mock_client
        
        abuse_ch = AbuseChFeedIngestion()
        abuse_ch.http_client = mock_client
        
        result = await abuse_ch.fetch_urlhaus()
        
        assert len(result) == 1
        assert result[0]["type"] == "url"
        assert "malicious.com" in result[0]["value"]
    
    @pytest.mark.asyncio
    async def test_ingest_all_feeds(self, sample_abuse_ch_data):
        """Test ingesting all Abuse.ch feeds."""
        abuse_ch = AbuseChFeedIngestion()
        
        # Mock the fetch methods
        abuse_ch.fetch_feodo_tracker = AsyncMock(return_value=[])
        abuse_ch.fetch_sslbl = AsyncMock(return_value=[])
        abuse_ch.fetch_urlhaus = AsyncMock(return_value=sample_abuse_ch_data["iocs"])
        
        result = await abuse_ch.ingest_all_feeds()
        
        assert "iocs" in result
        assert "total_count" in result
        assert result["total_count"] == 1
    
    @pytest.mark.asyncio
    async def test_ingest_all_feeds_with_errors(self):
        """Test ingesting feeds with errors."""
        abuse_ch = AbuseChFeedIngestion()
        
        # Mock one failing feed
        abuse_ch.fetch_feodo_tracker = AsyncMock(side_effect=Exception("Fetch error"))
        abuse_ch.fetch_sslbl = AsyncMock(return_value=[])
        abuse_ch.fetch_urlhaus = AsyncMock(return_value=[])
        
        result = await abuse_ch.ingest_all_feeds()
        
        assert "errors" in result["feed_results"]
        assert len(result["feed_results"]["errors"]) > 0
    
    @pytest.mark.asyncio
    async def test_close(self):
        """Test closing HTTP client."""
        abuse_ch = AbuseChFeedIngestion()
        abuse_ch.http_client = AsyncMock()
        
        await abuse_ch.close()
        abuse_ch.http_client.aclose.assert_called_once()
