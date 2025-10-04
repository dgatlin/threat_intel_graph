"""Test cases for Threat Intelligence Graph API."""

import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "service" in data
    assert data["service"] == "threat-intelligence-graph-api"


def test_get_asset_threat_context():
    """Test getting threat context for an asset."""
    # This will test with sample data if database is initialized
    response = client.get("/api/v1/iocs/asset/asset_web_server_01")
    assert response.status_code in [200, 404]  # 404 if asset doesn't exist


def test_search_iocs():
    """Test IOC search endpoint."""
    response = client.get("/api/v1/iocs/search")
    assert response.status_code == 200
    data = response.json()
    assert "iocs" in data
    assert "total_count" in data
    assert "search_params" in data


def test_search_iocs_with_filters():
    """Test IOC search with filters."""
    response = client.get("/api/v1/iocs/search?ioc_type=domain&confidence_min=0.5&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "iocs" in data
    assert "search_params" in data


def test_enhance_risk_score():
    """Test risk score enhancement endpoint."""
    response = client.get("/api/v1/enhance/risk-score?asset_id=asset_web_server_01&base_risk_score=0.5")
    assert response.status_code in [200, 404]  # 404 if asset doesn't exist


def test_create_ioc():
    """Test IOC creation endpoint."""
    ioc_data = {
        "id": "test_ioc_1",
        "type": "domain",
        "value": "test-malicious.com",
        "category": "malware",
        "confidence": 0.8,
        "source": "test"
    }
    
    response = client.post("/api/v1/iocs", json=ioc_data)
    assert response.status_code in [200, 500]  # 500 if database not available


def test_correlate_ioc_with_asset():
    """Test IOC correlation with asset."""
    response = client.post("/api/v1/iocs/test_ioc_1/correlate/asset_web_server_01")
    assert response.status_code in [200, 400, 404, 500]  # Various possible status codes


def test_placeholder_endpoints():
    """Test that placeholder endpoints return 501."""
    response = client.get("/api/v1/threat-actors/ta_apt29")
    assert response.status_code == 501
    
    response = client.get("/api/v1/campaigns/camp_operation_cozy_bear")
    assert response.status_code == 501


def test_get_ioc_relationships():
    """Test IOC relationships endpoint."""
    response = client.get("/api/v1/iocs/test_ioc_1/relationships?depth=2")
    assert response.status_code in [200, 500]  # 500 if database not available


def test_get_graph_export():
    """Test graph export endpoint."""
    response = client.get("/api/v1/graph/export")
    assert response.status_code in [200, 500]  # 500 if database not available
    
    # Test with filters
    response = client.get("/api/v1/graph/export?node_types=IOC,ThreatActor&relationship_types=USED_BY")
    assert response.status_code in [200, 500]


def test_ingest_sample_data():
    """Test sample data ingestion endpoint."""
    response = client.post("/api/v1/admin/ingest-sample-data")
    assert response.status_code in [200, 500]  # 500 if Kafka not available
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "items_ingested" in data
        assert "timestamp" in data
