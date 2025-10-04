"""Unit tests for IOC Service."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from api.services.ioc_service import IOCService
from api.models.ioc import IOC, IOCType, IOCCategory, IOCSearchRequest, IOCSearchResponse


class TestIOCService:
    """Test cases for IOC Service."""
    
    def test_init(self):
        """Test IOC service initialization."""
        service = IOCService()
        assert service is not None
        assert hasattr(service, 'logger')
    
    def test_calculate_threat_level_unknown(self):
        """Test threat level calculation with no IOCs."""
        service = IOCService()
        level = service._calculate_threat_level(0, 0.0)
        assert level == "unknown"
    
    def test_calculate_threat_level_critical(self):
        """Test threat level calculation for critical."""
        service = IOCService()
        level = service._calculate_threat_level(15, 0.9)
        assert level == "critical"
    
    def test_calculate_threat_level_high(self):
        """Test threat level calculation for high."""
        service = IOCService()
        level = service._calculate_threat_level(7, 0.7)
        assert level == "high"
    
    def test_calculate_threat_level_medium(self):
        """Test threat level calculation for medium."""
        service = IOCService()
        level = service._calculate_threat_level(3, 0.5)
        assert level == "medium"
    
    def test_calculate_threat_level_low(self):
        """Test threat level calculation for low."""
        service = IOCService()
        level = service._calculate_threat_level(1, 0.3)
        assert level == "low"
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_asset_threat_context_no_results(self, mock_execute_query):
        """Test getting asset threat context with no results."""
        mock_execute_query.return_value = []
        
        service = IOCService()
        result = await service.get_asset_threat_context("asset_001")
        
        assert result.asset_id == "asset_001"
        assert result.threat_level == "unknown"
        assert result.confidence == 0.0
        mock_execute_query.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_asset_threat_context_with_iocs(self, mock_execute_query, sample_ioc_data):
        """Test getting asset threat context with IOCs."""
        mock_record = {
            "ioc": sample_ioc_data,
            "ta": {"name": "Test Threat Actor"},
            "c": {"name": "Test Campaign"},
            "m": None,
            "ttp": {"mitre_id": "T1566"}
        }
        mock_execute_query.return_value = [mock_record]
        
        service = IOCService()
        result = await service.get_asset_threat_context("asset_001")
        
        assert result.asset_id == "asset_001"
        assert result.threat_level == "low"
        assert result.confidence == 0.85
        assert len(result.iocs) == 1
        assert "Test Threat Actor" in result.threat_actors
        assert "Test Campaign" in result.campaigns
        assert "T1566" in result.ttps
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_asset_threat_context_error_handling(self, mock_execute_query):
        """Test error handling in get_asset_threat_context."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = IOCService()
        result = await service.get_asset_threat_context("asset_001")
        
        assert result.asset_id == "asset_001"
        assert result.threat_level == "unknown"
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_search_iocs_basic(self, mock_execute_query, sample_ioc_data):
        """Test basic IOC search."""
        mock_execute_query.side_effect = [
            [{"ioc": sample_ioc_data}],  # First call for IOCs
            [{"total_count": 1}]  # Second call for count
        ]
        
        service = IOCService()
        search_params = IOCSearchRequest(offset=0, limit=10)
        result = await service.search_iocs(search_params)
        
        assert result.total_count == 1
        assert len(result.iocs) == 1
        assert result.iocs[0].id == sample_ioc_data["id"]
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_search_iocs_with_filters(self, mock_execute_query, sample_ioc_data):
        """Test IOC search with filters."""
        mock_execute_query.side_effect = [
            [{"ioc": sample_ioc_data}],
            [{"total_count": 1}]
        ]
        
        service = IOCService()
        search_params = IOCSearchRequest(
            ioc_type=IOCType.DOMAIN,
            confidence_min=0.5,
            offset=0,
            limit=10
        )
        result = await service.search_iocs(search_params)
        
        assert result.total_count == 1
        assert len(result.iocs) == 1
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_search_iocs_error_handling(self, mock_execute_query):
        """Test error handling in search_iocs."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = IOCService()
        search_params = IOCSearchRequest(offset=0, limit=10)
        result = await service.search_iocs(search_params)
        
        assert result.total_count == 0
        assert len(result.iocs) == 0
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_write_query')
    async def test_create_ioc_success(self, mock_execute_write_query, sample_ioc_data):
        """Test successful IOC creation."""
        mock_execute_write_query.return_value = [{"ioc": sample_ioc_data}]
        
        ioc = IOC(**sample_ioc_data)
        service = IOCService()
        result = await service.create_ioc(ioc)
        
        assert result.id == sample_ioc_data["id"]
        assert result.value == sample_ioc_data["value"]
        mock_execute_write_query.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_write_query')
    async def test_create_ioc_failure(self, mock_execute_write_query):
        """Test IOC creation failure."""
        mock_execute_write_query.side_effect = Exception("Database error")
        
        ioc_data = {
            "id": "test_ioc",
            "type": "domain",
            "value": "test.com",
            "category": "malware",
            "confidence": 0.8,
            "source": "test"
        }
        ioc = IOC(**ioc_data)
        service = IOCService()
        
        with pytest.raises(Exception):
            await service.create_ioc(ioc)
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_write_query')
    async def test_correlate_ioc_with_asset_success(self, mock_execute_write_query):
        """Test successful IOC-asset correlation."""
        mock_execute_write_query.return_value = [{"ioc": {}, "a": {}}]
        
        service = IOCService()
        result = await service.correlate_ioc_with_asset("ioc_001", "asset_001")
        
        assert result is True
        mock_execute_write_query.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_write_query')
    async def test_correlate_ioc_with_asset_failure(self, mock_execute_write_query):
        """Test IOC-asset correlation failure."""
        mock_execute_write_query.side_effect = Exception("Database error")
        
        service = IOCService()
        result = await service.correlate_ioc_with_asset("ioc_001", "asset_001")
        
        assert result is False
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_ioc_relationships_success(self, mock_execute_query):
        """Test successful IOC relationships retrieval."""
        # Create mock records that behave like Neo4j records
        mock_source = {"id": "ioc_1", "__labels__": ["IOC"]}
        mock_target = {"id": "ta_1", "__labels__": ["ThreatActor"]}
        mock_rel = {"type": "USED_BY"}
        
        mock_path_data = [
            {
                "source": mock_source,
                "target": mock_target,
                "relationships": [mock_rel],
                "path_length": 2
            }
        ]
        mock_execute_query.return_value = mock_path_data

        service = IOCService()
        result = await service.get_ioc_relationships("ioc_1", depth=2)

        assert len(result) == 1
        assert result[0]["source"] == "ioc_1"
        assert result[0]["target"] == "ta_1"
        mock_execute_query.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_ioc_relationships_error(self, mock_execute_query):
        """Test IOC relationships retrieval with error."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = IOCService()
        result = await service.get_ioc_relationships("ioc_1")
        
        assert result == []
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_graph_export_success(self, mock_execute_query):
        """Test successful graph export."""
        # Mock nodes data - execute_query returns records with "n" key
        nodes_data = [
            {"n": {"id": "ioc_1", "type": "domain"}},
            {"n": {"id": "ta_1", "name": "Test Actor"}}
        ]
        
        # Mock relationships data - execute_query returns records with "a", "r", "b" keys
        relationships_data = [
            {
                "a": {"id": "ioc_1"},
                "b": {"id": "ta_1"},
                "r": {"type": "USED_BY"}
            }
        ]
        
        mock_execute_query.side_effect = [nodes_data, relationships_data]
        
        service = IOCService()
        result = await service.get_graph_export(["IOC", "ThreatActor"], ["USED_BY"])
        
        assert result["node_count"] == 2
        assert result["relationship_count"] == 1
        assert len(result["nodes"]) == 2
        assert len(result["relationships"]) == 1
        assert "export_timestamp" in result
    
    @pytest.mark.asyncio
    @patch('api.services.ioc_service.execute_query')
    async def test_get_graph_export_error(self, mock_execute_query):
        """Test graph export with error."""
        mock_execute_query.side_effect = Exception("Database error")
        
        service = IOCService()
        result = await service.get_graph_export()
        
        assert "nodes" in result
        assert "relationships" in result
        assert "error" in result