"""Unit tests for Neo4j Connection."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from database.neo4j.connection import Neo4jConnection, execute_query, execute_write_query


class TestNeo4jConnection:
    """Test cases for Neo4j Connection."""
    
    def test_init(self):
        """Test Neo4j connection initialization."""
        conn = Neo4jConnection()
        assert conn is not None
        assert hasattr(conn, 'driver')
        assert hasattr(conn, '_connected')
    
    @patch('database.neo4j.connection.GraphDatabase')
    @patch('database.neo4j.connection.settings')
    def test_connect_success(self, mock_settings, mock_graph_db):
        """Test successful database connection."""
        mock_settings.neo4j_uri = "bolt://localhost:7687"
        mock_settings.neo4j_user = "neo4j"
        mock_settings.neo4j_password = "password"
        
        mock_driver = MagicMock()
        mock_graph_db.driver.return_value = mock_driver
        mock_driver.verify_connectivity.return_value = None
        
        conn = Neo4jConnection()
        result = conn.connect()
        
        assert result is True
        assert conn._connected is True
        mock_graph_db.driver.assert_called_once()
    
    @patch('database.neo4j.connection.GraphDatabase')
    @patch('database.neo4j.connection.settings')
    def test_connect_failure(self, mock_settings, mock_graph_db):
        """Test failed database connection."""
        mock_settings.neo4j_uri = "bolt://localhost:7687"
        mock_settings.neo4j_user = "neo4j"
        mock_settings.neo4j_password = "password"
        
        mock_graph_db.driver.side_effect = Exception("Connection failed")
        
        conn = Neo4jConnection()
        result = conn.connect()
        
        assert result is False
        assert conn._connected is False
    
    def test_close(self):
        """Test closing database connection."""
        conn = Neo4jConnection()
        mock_driver = MagicMock()
        conn.driver = mock_driver
        conn._connected = True
        
        conn.close()
        
        mock_driver.close.assert_called_once()
        assert conn._connected is False
    
    def test_is_connected(self):
        """Test connection status check."""
        conn = Neo4jConnection()
        
        assert conn.is_connected() is False
        
        conn._connected = True
        assert conn.is_connected() is True
    
    @patch('database.neo4j.connection.neo4j_connection')
    def test_execute_query_success(self, mock_connection):
        """Test successful query execution."""
        mock_session = MagicMock()
        mock_record = MagicMock()
        mock_record.data.return_value = {"node": {"id": "test"}}
        mock_session.run.return_value = [mock_record]
        
        # Set up the session context manager properly
        mock_connection.get_session.return_value.__enter__.return_value = mock_session
        mock_connection.get_session.return_value.__exit__.return_value = None
        mock_connection.is_connected.return_value = True
        
        query = "MATCH (n) RETURN n"
        result = execute_query(query, {})
        
        assert len(result) == 1
        mock_session.run.assert_called_once()
    
    @patch('database.neo4j.connection.neo4j_connection')
    def test_execute_query_not_connected(self, mock_connection):
        """Test query execution when not connected."""
        mock_connection.is_connected.return_value = False
        
        query = "MATCH (n) RETURN n"
        result = execute_query(query, {})
        
        assert result == []
    
    @patch('database.neo4j.connection.neo4j_connection')
    def test_execute_write_query_success(self, mock_connection):
        """Test successful write query execution."""
        mock_session = MagicMock()
        mock_record = MagicMock()
        mock_record.data.return_value = {"node": {"id": "test"}}
        mock_session.run.return_value = [mock_record]
        
        # Set up the session context manager properly
        mock_connection.get_session.return_value.__enter__.return_value = mock_session
        mock_connection.get_session.return_value.__exit__.return_value = None
        mock_connection.is_connected.return_value = True
        
        query = "CREATE (n:Test {id: $id}) RETURN n"
        result = execute_write_query(query, {"id": "test"})
        
        assert len(result) == 1
        mock_session.run.assert_called_once()
    
    @patch('database.neo4j.connection.neo4j_connection')
    def test_execute_write_query_error(self, mock_connection):
        """Test write query execution with error."""
        mock_session = MagicMock()
        mock_session.run.side_effect = Exception("Query failed")
        
        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__.return_value = mock_session
        
        mock_connection.driver = mock_driver
        mock_connection.is_connected.return_value = True
        
        query = "CREATE (n:Test {id: $id}) RETURN n"
        result = execute_write_query(query, {"id": "test"})
        
        assert result == []
