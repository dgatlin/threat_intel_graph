"""Unit tests for Data Models."""

import pytest
from datetime import datetime
from pydantic import ValidationError
from api.models.ioc import IOC, IOCType, IOCCategory, IOCSearchRequest, AssetThreatContext
from api.models.threat_actor import ThreatActor
from api.models.campaign import Campaign


class TestIOCModel:
    """Test cases for IOC model."""
    
    def test_ioc_creation_valid(self, sample_ioc_data):
        """Test valid IOC creation."""
        ioc = IOC(**sample_ioc_data)
        assert ioc.id == sample_ioc_data["id"]
        assert ioc.type == IOCType.DOMAIN
        assert ioc.value == sample_ioc_data["value"]
        assert ioc.confidence == sample_ioc_data["confidence"]
    
    def test_ioc_creation_minimal(self):
        """Test IOC creation with minimal required fields."""
        ioc = IOC(
            id="ioc_min",
            type="domain",
            value="test.com",
            category="malware",
            confidence=0.5,
            source="test"
        )
        assert ioc.id == "ioc_min"
        assert ioc.type == IOCType.DOMAIN
    
    def test_ioc_invalid_confidence(self):
        """Test IOC creation with invalid confidence value."""
        with pytest.raises(ValidationError):
            IOC(
                id="ioc_invalid",
                type="domain",
                value="test.com",
                category="malware",
                confidence=1.5,  # Invalid: > 1.0
                source="test"
            )
    
    def test_ioc_type_enum(self):
        """Test IOC type enum values."""
        assert IOCType.DOMAIN.value == "domain"
        assert IOCType.IP.value == "ip"
        assert IOCType.HASH.value == "hash"
        assert IOCType.URL.value == "url"
        assert IOCType.EMAIL.value == "email"
    
    def test_ioc_category_enum(self):
        """Test IOC category enum values."""
        assert IOCCategory.MALWARE.value == "malware"
        assert IOCCategory.PHISHING.value == "phishing"
        assert IOCCategory.C2.value == "c2"


class TestIOCSearchRequest:
    """Test cases for IOC Search Request model."""
    
    def test_search_request_defaults(self):
        """Test search request with default values."""
        request = IOCSearchRequest()
        assert request.offset == 0
        assert request.limit == 100
        assert request.asset_id is None
        assert request.ioc_type is None
    
    def test_search_request_with_filters(self):
        """Test search request with filters."""
        request = IOCSearchRequest(
            asset_id="asset_001",
            ioc_type=IOCType.DOMAIN,
            confidence_min=0.7,
            offset=10,
            limit=50
        )
        assert request.asset_id == "asset_001"
        assert request.ioc_type == IOCType.DOMAIN
        assert request.confidence_min == 0.7
        assert request.offset == 10
        assert request.limit == 50


class TestAssetThreatContext:
    """Test cases for Asset Threat Context model."""
    
    def test_asset_threat_context_minimal(self):
        """Test minimal asset threat context."""
        context = AssetThreatContext(
            asset_id="asset_001",
            threat_level="unknown",
            confidence=0.0
        )
        assert context.asset_id == "asset_001"
        assert context.threat_level == "unknown"
        assert context.threat_actors == []
        assert context.iocs == []
    
    def test_asset_threat_context_complete(self, sample_ioc_data):
        """Test complete asset threat context."""
        ioc = IOC(**sample_ioc_data)
        context = AssetThreatContext(
            asset_id="asset_001",
            threat_level="high",
            threat_actors=["APT29", "APT28"],
            iocs=[ioc],
            campaigns=["Operation Ghost"],
            ttps=["T1566", "T1059"],
            confidence=0.85
        )
        assert context.asset_id == "asset_001"
        assert context.threat_level == "high"
        assert len(context.threat_actors) == 2
        assert len(context.iocs) == 1
        assert context.confidence == 0.85


class TestThreatActorModel:
    """Test cases for Threat Actor model."""
    
    def test_threat_actor_creation(self, sample_threat_actor_data):
        """Test valid threat actor creation."""
        actor = ThreatActor(**sample_threat_actor_data)
        assert actor.id == sample_threat_actor_data["id"]
        assert actor.name == sample_threat_actor_data["name"]
        assert len(actor.aliases) == 2
        assert actor.motivation == sample_threat_actor_data["motivation"]
    
    def test_threat_actor_minimal(self):
        """Test threat actor with minimal fields."""
        actor = ThreatActor(
            id="ta_min",
            name="Test Actor",
            confidence=0.7
        )
        assert actor.id == "ta_min"
        assert actor.name == "Test Actor"
        assert actor.aliases == []


class TestCampaignModel:
    """Test cases for Campaign model."""
    
    def test_campaign_creation(self, sample_campaign_data):
        """Test valid campaign creation."""
        campaign = Campaign(**sample_campaign_data)
        assert campaign.id == sample_campaign_data["id"]
        assert campaign.name == sample_campaign_data["name"]
        assert campaign.status == sample_campaign_data["status"]
        assert len(campaign.objectives) == 2
    
    def test_campaign_minimal(self):
        """Test campaign with minimal fields."""
        campaign = Campaign(
            id="camp_min",
            name="Test Campaign"
        )
        assert campaign.id == "camp_min"
        assert campaign.name == "Test Campaign"
        assert campaign.objectives == []
