"""Integration tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from api.main import app


client = TestClient(app)


class TestHealthEndpoint:
    """Integration tests for health check endpoint."""
    
    def test_health_check(self):
        """Test health check endpoint returns correct status."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert "service" in data
        assert data["service"] == "threat-intelligence-graph-api"
        assert "timestamp" in data


class TestIOCEndpoints:
    """Integration tests for IOC endpoints."""
    
    @patch('api.services.ioc_service.execute_query')
    def test_search_iocs_empty_results(self, mock_execute_query):
        """Test IOC search with no results."""
        mock_execute_query.return_value = []
        
        response = client.get("/api/v1/iocs/search")
        assert response.status_code == 200
        
        data = response.json()
        assert "iocs" in data
        assert "total_count" in data
        assert data["total_count"] == 0
    
    @patch('api.services.ioc_service.execute_query')
    def test_search_iocs_with_type_filter(self, mock_execute_query):
        """Test IOC search with type filter."""
        mock_execute_query.side_effect = [
            [{"ioc": {"id": "test", "type": "domain", "value": "test.com", 
                     "category": "malware", "confidence": 0.8, "source": "test"}}],
            [{"total_count": 1}]
        ]
        
        response = client.get("/api/v1/iocs/search?ioc_type=domain")
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["iocs"]) == 1
        assert data["iocs"][0]["type"] == "domain"
    
    @patch('api.services.ioc_service.execute_query')
    def test_search_iocs_with_confidence_filter(self, mock_execute_query):
        """Test IOC search with confidence filter."""
        mock_execute_query.side_effect = [
            [{"ioc": {"id": "test", "type": "domain", "value": "test.com", 
                     "category": "malware", "confidence": 0.9, "source": "test"}}],
            [{"total_count": 1}]
        ]
        
        response = client.get("/api/v1/iocs/search?confidence_min=0.7")
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["iocs"]) == 1
        assert data["iocs"][0]["confidence"] >= 0.7
    
    @patch('api.services.ioc_service.execute_write_query')
    def test_create_ioc(self, mock_execute_write_query):
        """Test IOC creation."""
        ioc_data = {
            "id": "test_ioc_integration",
            "type": "domain",
            "value": "test-integration.com",
            "category": "malware",
            "confidence": 0.85,
            "source": "integration_test"
        }
        
        mock_execute_write_query.return_value = [{"ioc": ioc_data}]
        
        response = client.post("/api/v1/iocs", json=ioc_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == ioc_data["id"]
        assert data["value"] == ioc_data["value"]
    
    @patch('api.services.ioc_service.execute_query')
    def test_get_asset_threat_context(self, mock_execute_query):
        """Test getting asset threat context."""
        mock_execute_query.return_value = []
        
        response = client.get("/api/v1/iocs/asset/asset_web_server_01")
        assert response.status_code == 200
        
        data = response.json()
        assert "asset_id" in data
        assert data["asset_id"] == "asset_web_server_01"
        assert "threat_level" in data
    
    @patch('api.services.ioc_service.execute_write_query')
    def test_correlate_ioc_with_asset(self, mock_execute_write_query):
        """Test IOC correlation with asset."""
        mock_execute_write_query.return_value = [{"ioc": {}, "a": {}}]
        
        response = client.post("/api/v1/iocs/test_ioc/correlate/asset_001")
        assert response.status_code == 200
        
        data = response.json()
        assert data["success"] is True


class TestEnhanceEndpoint:
    """Integration tests for enhancement endpoints."""
    
    @patch('api.services.ioc_service.execute_query')
    def test_enhance_risk_score_no_context(self, mock_execute_query):
        """Test risk score enhancement with no threat context."""
        mock_execute_query.return_value = []
        
        response = client.get("/api/v1/enhance/risk-score?asset_id=asset_001&base_risk_score=0.5")
        assert response.status_code == 200
        
        data = response.json()
        assert "enhanced_risk_score" in data
        assert "base_risk_score" in data
        assert data["base_risk_score"] == 0.5
    
    @patch('api.services.ioc_service.execute_query')
    def test_enhance_risk_score_with_context(self, mock_execute_query):
        """Test risk score enhancement with threat context."""
        mock_execute_query.return_value = [
            {"ioc": {"id": "test", "type": "domain", "value": "test.com", 
                    "category": "malware", "confidence": 0.9, "source": "test"},
             "ta": {"name": "APT29"},
             "c": None,
             "m": None,
             "ttp": None}
        ]
        
        response = client.get("/api/v1/enhance/risk-score?asset_id=asset_001&base_risk_score=0.5")
        assert response.status_code == 200
        
        data = response.json()
        assert data["enhanced_risk_score"] > data["base_risk_score"]
        assert "threat_context" in data


class TestPlaceholderEndpoints:
    """Integration tests for placeholder endpoints."""
    
    def test_get_threat_actor_not_implemented(self):
        """Test threat actor endpoint returns 501."""
        response = client.get("/api/v1/threat-actors/ta_apt29")
        assert response.status_code == 501
        
        data = response.json()
        assert "detail" in data
        assert "not implemented" in data["detail"].lower()
    
    def test_get_campaign_not_implemented(self):
        """Test campaign endpoint returns 501."""
        response = client.get("/api/v1/campaigns/camp_operation_cozy_bear")
        assert response.status_code == 501
        
        data = response.json()
        assert "detail" in data
        assert "not implemented" in data["detail"].lower()


class TestErrorHandling:
    """Integration tests for error handling."""
    
    def test_invalid_ioc_type(self):
        """Test search with invalid IOC type."""
        response = client.get("/api/v1/iocs/search?ioc_type=invalid_type")
        assert response.status_code == 422  # Validation error
    
    def test_invalid_confidence_range(self):
        """Test search with invalid confidence value."""
        response = client.get("/api/v1/iocs/search?confidence_min=1.5")
        assert response.status_code == 422  # Validation error
    
    def test_missing_required_fields_create_ioc(self):
        """Test IOC creation with missing required fields."""
        incomplete_ioc = {
            "id": "test_incomplete",
            "type": "domain"
            # Missing required fields
        }
        
        response = client.post("/api/v1/iocs", json=incomplete_ioc)
        assert response.status_code == 422  # Validation error
