"""Neo4j database connection and session management."""

from neo4j import GraphDatabase, Driver
from typing import Optional, Dict, Any, List
import structlog
from config.settings import settings

logger = structlog.get_logger(__name__)


class Neo4jConnection:
    """Neo4j database connection manager."""
    
    def __init__(self):
        self.driver: Optional[Driver] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish connection to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password)
            )
            
            # Test connection
            with self.driver.session(database=settings.neo4j_database) as session:
                session.run("RETURN 1")
            
            logger.info(
                "Neo4j connection established",
                uri=settings.neo4j_uri,
                database=settings.neo4j_database
            )
            
        except Exception as e:
            logger.error(
                "Failed to connect to Neo4j",
                error=str(e),
                uri=settings.neo4j_uri
            )
            raise
    
    def get_session(self):
        """Get a Neo4j session."""
        if not self.driver:
            self._connect()
        return self.driver.session(database=settings.neo4j_database)
    
    def close(self) -> None:
        """Close the database connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def health_check(self) -> bool:
        """Check if the database connection is healthy."""
        try:
            with self.get_session() as session:
                result = session.run("RETURN 1 as health")
                return result.single()["health"] == 1
        except Exception as e:
            logger.error("Neo4j health check failed", error=str(e))
            return False


# Global connection instance
neo4j_connection = Neo4jConnection()


def get_neo4j_session():
    """Get a Neo4j session for dependency injection."""
    return neo4j_connection.get_session()


def execute_query(query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Execute a Cypher query and return results."""
    with neo4j_connection.get_session() as session:
        result = session.run(query, parameters or {})
        return [dict(record) for record in result]


def execute_write_query(query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Execute a write Cypher query and return results."""
    with neo4j_connection.get_session() as session:
        result = session.run(query, parameters or {})
        return [dict(record) for record in result]