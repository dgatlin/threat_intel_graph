"""Pytest configuration and fixtures for Threat Intelligence Graph tests."""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime
from typing import Dict, Any


@pytest.fixture
def mock_neo4j_driver():
    """Mock Neo4j driver for testing."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    return driver


@pytest.fixture
def mock_neo4j_connection(mock_neo4j_driver):
    """Mock Neo4j connection."""
    from database.neo4j.connection import Neo4jConnection
    
    connection = Neo4jConnection()
    connection.driver = mock_neo4j_driver
    connection._connected = True
    return connection


@pytest.fixture
def sample_ioc_data() -> Dict[str, Any]:
    """Sample IOC data for testing."""
    return {
        "id": "ioc_test_001",
        "type": "domain",
        "value": "malicious-test.com",
        "category": "malware",
        "confidence": 0.85,
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "source": "test_source",
        "tags": ["malware", "phishing"],
        "metadata": {
            "threat_level": "high",
            "country": "unknown"
        }
    }


@pytest.fixture
def sample_threat_actor_data() -> Dict[str, Any]:
    """Sample threat actor data for testing."""
    return {
        "id": "ta_test_001",
        "name": "Test APT Group",
        "aliases": ["APT-TEST", "Test Group"],
        "motivation": "financial",
        "sophistication": "advanced",
        "country": "unknown",
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "source": "test_source",
        "description": "Test threat actor for unit testing"
    }


@pytest.fixture
def sample_campaign_data() -> Dict[str, Any]:
    """Sample campaign data for testing."""
    return {
        "id": "camp_test_001",
        "name": "Test Campaign",
        "description": "Test campaign for unit testing",
        "start_date": datetime.utcnow().isoformat(),
        "end_date": None,
        "status": "active",
        "objectives": ["data_theft", "espionage"],
        "threat_actors": ["ta_test_001"],
        "source": "test_source",
        "confidence": 0.8
    }


@pytest.fixture
def sample_otx_pulse() -> Dict[str, Any]:
    """Sample OTX pulse data for testing."""
    return {
        "id": "pulse_test_001",
        "name": "Test Threat Pulse",
        "description": "Test pulse from OTX",
        "author": {"username": "test_user"},
        "created": datetime.utcnow().isoformat(),
        "modified": datetime.utcnow().isoformat(),
        "tags": ["malware", "test"],
        "indicators": [
            {
                "type": "domain",
                "indicator": "test-malicious.com",
                "created": datetime.utcnow().isoformat()
            }
        ]
    }


@pytest.fixture
def sample_abuse_ch_data() -> Dict[str, Any]:
    """Sample Abuse.ch feed data for testing."""
    return {
        "iocs": [
            {
                "id": "abuse_ch_test_001",
                "type": "url",
                "value": "http://malicious-test.com/payload",
                "confidence": 0.9,
                "source": "abuse_ch_urlhaus",
                "category": "malicious_url"
            }
        ],
        "total_count": 1
    }


@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer for testing."""
    producer = MagicMock()
    producer.send.return_value.get.return_value = True
    return producer


@pytest.fixture
def mock_kafka_consumer():
    """Mock Kafka consumer for testing."""
    consumer = MagicMock()
    consumer.poll.return_value = {}
    return consumer


@pytest.fixture
def mock_httpx_client():
    """Mock httpx AsyncClient for testing."""
    client = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"success": True}
    client.get.return_value = response
    client.post.return_value = response
    return client
