"""Unit tests for Campaign Service."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from api.services.campaign_service import CampaignService
from api.models.campaign import Campaign, CampaignSearchRequest, CampaignSearchResponse


class TestCampaignService:
    """Test cases for Campaign Service."""
    
    def test_init(self):
        """Test campaign service initialization."""
        service = CampaignService()
        assert service is not None
        assert hasattr(service, 'logger')
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_get_campaign_success(self, mock_execute_query):
        """Test successful campaign retrieval."""
        mock_record = {
            "c": {
                "id": "camp_001",
                "name": "Test Campaign",
                "description": "Test campaign description",
                "status": "active",
                "start_date": "2023-01-01",
                "end_date": None
            },
            "threat_actors": [{"name": "Test Actor"}],
            "iocs": [{"id": "ioc_001"}],
            "ttps": [{"mitre_id": "T1566"}],
            "assets": [{"id": "asset_001"}]
        }
        mock_execute_query.return_value = [mock_record]
        
        service = CampaignService()
        result = await service.get_campaign("camp_001")
        
        assert result is not None
        assert result.id == "camp_001"
        assert result.name == "Test Campaign"
        assert "Test Actor" in result.threat_actors
        assert "ioc_001" in result.iocs
        assert "T1566" in result.ttps
        assert "asset_001" in result.target_organizations
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_get_campaign_not_found(self, mock_execute_query):
        """Test campaign retrieval when not found."""
        mock_execute_query.return_value = []
        
        service = CampaignService()
        result = await service.get_campaign("nonexistent")
        
        assert result is None
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_get_campaign_error(self, mock_execute_query):
        """Test campaign retrieval with error."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = CampaignService()
        result = await service.get_campaign("camp_001")
        
        assert result is None
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_search_campaigns_success(self, mock_execute_query):
        """Test successful campaign search."""
        mock_records = [
            {
                "c": {"id": "camp_001", "name": "Campaign 1", "status": "active"},
                "ta": {"name": "Actor 1"}
            },
            {
                "c": {"id": "camp_002", "name": "Campaign 2", "status": "active"},
                "ta": {"name": "Actor 2"}
            }
        ]
        mock_execute_query.side_effect = [mock_records, [{"total_count": 2}]]
        
        service = CampaignService()
        search_params = CampaignSearchRequest(offset=0, limit=10)
        result = await service.search_campaigns(search_params)
        
        assert result.total_count == 2
        assert len(result.campaigns) == 2
        assert result.campaigns[0].id == "camp_001"
        assert result.campaigns[1].id == "camp_002"
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_search_campaigns_with_filters(self, mock_execute_query):
        """Test campaign search with filters."""
        mock_records = [
            {
                "c": {"id": "camp_001", "name": "Test Campaign", "status": "active"},
                "ta": {"name": "Test Actor"}
            }
        ]
        mock_execute_query.side_effect = [mock_records, [{"total_count": 1}]]
        
        service = CampaignService()
        search_params = CampaignSearchRequest(
            threat_actor="Test Actor",
            status="active",
            offset=0,
            limit=10
        )
        result = await service.search_campaigns(search_params)
        
        assert result.total_count == 1
        assert len(result.campaigns) == 1
        assert result.campaigns[0].name == "Test Campaign"
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_search_campaigns_error(self, mock_execute_query):
        """Test campaign search with error."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = CampaignService()
        search_params = CampaignSearchRequest(offset=0, limit=10)
        result = await service.search_campaigns(search_params)
        
        assert result.total_count == 0
        assert len(result.campaigns) == 0
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_write_query')
    async def test_create_campaign_success(self, mock_execute_write_query):
        """Test successful campaign creation."""
        mock_execute_write_query.return_value = [{"c": {"id": "camp_001"}}]
        
        campaign_data = {
            "id": "camp_001",
            "name": "Test Campaign",
            "description": "Test description",
            "status": "active",
            "objectives": ["Test objective"]
        }
        campaign = Campaign(**campaign_data)
        
        service = CampaignService()
        result = await service.create_campaign(campaign)
        
        assert result.id == "camp_001"
        mock_execute_write_query.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_write_query')
    async def test_create_campaign_failure(self, mock_execute_write_query):
        """Test campaign creation failure."""
        mock_execute_write_query.side_effect = Exception("Database error")
        
        campaign_data = {
            "id": "camp_001",
            "name": "Test Campaign",
            "description": "Test description",
            "status": "active",
            "objectives": ["Test objective"]
        }
        campaign = Campaign(**campaign_data)
        
        service = CampaignService()
        
        with pytest.raises(Exception):
            await service.create_campaign(campaign)
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_analyze_campaign_timeline_success(self, mock_execute_query):
        """Test successful campaign timeline analysis."""
        mock_campaign_data = {
            "c": {
                "id": "camp_001",
                "name": "Test Campaign",
                "start_date": "2023-01-01",
                "end_date": "2023-12-31"
            },
            "iocs": [
                {"id": "ioc_001", "type": "domain", "value": "test.com", "first_seen": "2023-01-15", "confidence": 0.8}
            ],
            "ttps": [
                {"mitre_id": "T1566", "name": "Phishing"}
            ]
        }
        mock_execute_query.return_value = [mock_campaign_data]
        
        service = CampaignService()
        result = await service.analyze_campaign_timeline("camp_001")
        
        assert result.campaign_id == "camp_001"
        assert len(result.timeline_events) > 0
        assert len(result.key_milestones) > 0
        assert len(result.ioc_timeline) == 1
        assert len(result.ttp_evolution) == 1
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_analyze_campaign_timeline_not_found(self, mock_execute_query):
        """Test campaign timeline analysis when campaign not found."""
        mock_execute_query.return_value = []
        
        service = CampaignService()
        result = await service.analyze_campaign_timeline("nonexistent")
        
        assert result.campaign_id == "nonexistent"
        assert len(result.timeline_events) == 0
        assert len(result.key_milestones) == 0
    
    @pytest.mark.asyncio
    @patch('api.services.campaign_service.execute_query')
    async def test_analyze_campaign_timeline_error(self, mock_execute_query):
        """Test campaign timeline analysis with error."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = CampaignService()
        result = await service.analyze_campaign_timeline("camp_001")
        
        assert result.campaign_id == "camp_001"
        assert len(result.timeline_events) == 0
