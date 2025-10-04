# Threat Intelligence Graph - Data Architecture

## Overview

This document describes the data inputs, processing pipeline, and graph structure of the Threat Intelligence Graph system. The system ingests threat intelligence from multiple external sources, processes it through Kafka streams, and stores it in a Neo4j graph database with rich relationships between threat entities.

## Table of Contents

1. [Data Sources](#data-sources)
2. [Data Processing Pipeline](#data-processing-pipeline)
3. [System Architecture Diagram](#system-architecture-diagram)
4. [Graph Structure](#graph-structure)
5. [Data Models](#data-models)
6. [Relationship Types](#relationship-types)
7. [Current Data Status](#current-data-status)
8. [API Integration](#api-integration)
9. [Quick Reference](#quick-reference)

## Data Sources

### 1. Abuse.ch Feeds (✅ Active)
- **URLhaus**: Malware distribution URLs
- **Feodo Tracker**: Botnet C&C servers
- **SSL Blacklist**: Malicious SSL certificates
- **API Required**: None (public feeds)
- **Data Format**: CSV/TXT files
- **Update Frequency**: Real-time
- **Current Volume**: 74,539 IOCs

### 2. Open Threat Exchange (OTX) (✅ Active)
- **Pulse Data**: Threat intelligence reports with IOCs, threat actors, campaigns
- **API Required**: Free account with API key
- **Data Format**: JSON via REST API
- **Update Frequency**: 24 hours
- **Current Volume**: 834 IOCs from 23 pulses

### 3. VirusTotal (⚠️ Configured)
- **Intelligence Search**: Domain, IP, URL, file hash analysis
- **API Required**: Free/Paid tier API key
- **Data Format**: JSON via REST API
- **Update Frequency**: On-demand
- **Status**: API key configured, permissions issue (403 error)

### 4. MISP (❌ Placeholder)
- **Event Data**: Structured threat intelligence events
- **API Required**: MISP instance URL and API key
- **Data Format**: JSON via REST API
- **Update Frequency**: Real-time
- **Status**: Using placeholder configuration

### 5. Custom Threat Feeds (❌ Placeholder)
- **Custom Sources**: Organization-specific threat feeds
- **API Required**: Custom API key
- **Data Format**: JSON/CSV
- **Update Frequency**: Configurable
- **Status**: Using placeholder configuration

## Data Processing Pipeline

### 1. Ingestion Layer
```
External Feeds → Threat Feed Service → Kafka Topics
```

**Components:**
- `data/ingestion/feed_service.py`: Orchestrates multi-source ingestion
- `data/ingestion/abuse_ch_feeds.py`: Handles Abuse.ch feeds
- `data/ingestion/otx_feeds.py`: Handles OTX API integration
- `streaming/kafka_producer.py`: Sends data to Kafka topics

**Kafka Topics:**
- `threat_intelligence`: Main threat data (IOCs, threat actors, campaigns)
- `ioc_correlation`: Asset-IOC correlation data

### 2. Streaming Processing
```
Kafka Topics → Kafka Consumer → Data Processor → Neo4j
```

**Components:**
- `streaming/kafka_consumer.py`: Consumes messages from Kafka
- `streaming/kafka_processor.py`: Processes and normalizes data
- `database/neo4j/connection.py`: Manages Neo4j connections

### 3. Data Normalization
**IOC Normalization:**
- Standardizes IOC types (domain, ip_address, hash, url, email)
- Maps external types to internal schema
- Adds metadata (confidence, source, timestamps)

**Relationship Extraction:**
- Extracts threat actors from pulse names/descriptions
- Identifies campaigns from operation names
- Creates associations between IOCs and threat entities

## System Architecture Diagram

### Overall System Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   External      │    │   External      │    │   External      │
│   Data Sources  │    │   Data Sources  │    │   Data Sources  │
│                 │    │                 │    │                 │
│ • Abuse.ch      │    │ • OTX           │    │ • VirusTotal    │
│ • MISP          │    │ • Custom Feeds  │    │ • STIX/TAXII    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │   Threat Feed Service     │
                    │   (Ingestion Layer)       │
                    │                           │
                    │ • Data Normalization      │
                    │ • Relationship Extraction │
                    │ • Quality Validation      │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │      Kafka Topics         │
                    │                           │
                    │ • threat_intelligence     │
                    │ • ioc_correlation         │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Kafka Consumer          │
                    │   (Streaming Layer)       │
                    │                           │
                    │ • Message Processing      │
                    │ • Data Transformation     │
                    │ • Error Handling          │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    Neo4j Graph DB         │
                    │   (Storage Layer)         │
                    │                           │
                    │ • IOC Nodes (74,546)      │
                    │ • ThreatActor Nodes (4)   │
                    │ • Campaign Nodes (3)      │
                    │ • Asset Nodes (2)         │
                    │ • Relationships (14)      │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    FastAPI Service        │
                    │   (API Layer)             │
                    │                           │
                    │ • REST Endpoints          │
                    │ • Graph Queries           │
                    │ • Data Export             │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   External Integration    │
                    │                           │
                    │ • GNN Attack Path Project │
                    │ • SIEM Systems            │
                    │ • Security Tools          │
                    └───────────────────────────┘
```

### Node Relationships
```
┌─────────────┐    USED_BY     ┌─────────────┐    BELONGS_TO    ┌─────────────┐
│     IOC     │───────────────▶│ThreatActor  │─────────────────▶│  Campaign   │
│             │                │             │                  │             │
│ • Domain    │                │ • Lazarus   │                  │ • Operation │
│ • IP        │                │ • NoisyBear │                  │ • RAT Camp  │
│ • Hash      │                │ • APT29     │                  │ • Influence │
│ • URL       │                │ • Russian   │                  │             │
└─────────────┘                └─────────────┘                  └─────────────┘
       │                                │                                │
       │                                │                                │
       │ EXPOSED_TO                     │ USES                          │ INVOLVES
       │                                │                                │
       ▼                                ▼                                ▼
┌─────────────┐                ┌─────────────┐                  ┌─────────────┐
│    Asset    │                │    Asset    │                  │     IOC     │
│             │                │             │                  │             │
│ • Server    │                │ • Server    │                  │ • Campaign  │
│ • Workstation│               │ • Workstation│                 │   IOCs      │
│ • Network   │                │ • Network   │                  │             │
└─────────────┘                └─────────────┘                  └─────────────┘
```

## Graph Structure

### Node Types

#### 1. IOC (Indicators of Compromise)
```cypher
(:IOC {
  id: String,
  type: String,        // domain, ip_address, hash, url, email
  value: String,       // The actual IOC value
  category: String,    // malware, phishing, command_and_control
  confidence: Float,   // 0.0 - 1.0
  source: String,      // abuse_ch, otx, virustotal, misp
  first_seen: DateTime,
  last_seen: DateTime
})
```

#### 2. ThreatActor
```cypher
(:ThreatActor {
  id: String,
  name: String,
  aliases: [String],
  country: String,
  motivation: String,    // financial, espionage, hacktivism
  sophistication: String, // low, medium, high, advanced
  status: String,        // active, inactive, unknown
  source: String,
  first_seen: DateTime,
  last_seen: DateTime
})
```

#### 3. Campaign
```cypher
(:Campaign {
  id: String,
  name: String,
  description: String,
  status: String,        // active, inactive, completed
  objectives: [String],  // data_theft, espionage, financial
  start_date: DateTime,
  end_date: DateTime,
  source: String,
  confidence: Float
})
```

#### 4. Asset
```cypher
(:Asset {
  id: String,
  name: String,
  type: String,          // server, workstation, network
  ip_address: String,
  operating_system: String,
  risk_score: Float,
  threat_level: String,  // low, medium, high, critical
  last_updated: DateTime
})
```

### Current Node Counts
- **IOC**: 74,546 nodes
- **ThreatActor**: 4 nodes
- **Campaign**: 3 nodes
- **Asset**: 2 nodes

## Data Models

### Pydantic Models

#### IOC Model
```python
class IOCType(str, Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"

class IOCCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    COMMAND_AND_CONTROL = "command_and_control"
    ATTACK_INFRASTRUCTURE = "attack_infrastructure"

class IOC(BaseModel):
    id: str
    type: IOCType
    value: str
    category: IOCCategory
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    first_seen: datetime
    last_seen: datetime
```

#### ThreatActor Model
```python
class ThreatActor(BaseModel):
    id: str
    name: str
    aliases: List[str] = []
    country: str = "unknown"
    motivation: str = "unknown"
    sophistication: str = "unknown"
    status: str = "active"
    source: str
    first_seen: datetime
    last_seen: datetime
```

#### Campaign Model
```python
class Campaign(BaseModel):
    id: str
    name: str
    description: str = ""
    status: str = "active"
    objectives: List[str] = []
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
```

## Relationship Types

### Current Relationships (14 total)

#### 1. USED_BY (8 relationships)
```cypher
(IOC)-[:USED_BY]->(ThreatActor)
```
**Purpose**: Links IOCs to the threat actors that use them
**Examples**: 
- Lazarus Group uses 5 IOCs
- NoisyBear uses 3 IOCs

#### 2. BELONGS_TO (3 relationships)
```cypher
(ThreatActor)-[:BELONGS_TO]->(Campaign)
```
**Purpose**: Associates threat actors with campaigns
**Examples**:
- Lazarus Group → Lazarus RAT Campaign
- NoisyBear → Operation BarrelFire
- Russian Threat Group → Russian Influence Operations - Moldova

#### 3. EXPOSED_TO (2 relationships)
```cypher
(Asset)-[:EXPOSED_TO]->(IOC)
```
**Purpose**: Indicates assets exposed to specific IOCs
**Usage**: Integration with existing GNN attack path project

#### 4. USES (1 relationship)
```cypher
(Asset)-[:USES]->(ThreatActor)
```
**Purpose**: Links assets to threat actors (for risk assessment)

### Planned Relationships

#### IOC Relationships
```cypher
(IOC)-[:ASSOCIATED_WITH]->(Malware)
(IOC)-[:RESOLVES_TO]->(IOC)
(IOC)-[:OBSERVED_ON]->(Asset)
(IOC)-[:SEEN_IN]->(Campaign)
```

#### Campaign Relationships
```cypher
(Campaign)-[:USES]->(TTP)
(Campaign)-[:TARGETS]->(Asset)
(Campaign)-[:INVOLVES]->(IOC)
```

#### Threat Actor Relationships
```cypher
(ThreatActor)-[:USES]->(TTP)
(ThreatActor)-[:CONTROLS]->(IOC)
(ThreatActor)-[:DEVELOPS]->(Malware)
(ThreatActor)-[:TARGETS]->(Organization)
```

## Current Data Status

### Data Volume
- **Total Nodes**: 74,556
- **Total Relationships**: 14
- **Data Sources**: 2 active (Abuse.ch, OTX), 3 configured (VirusTotal, MISP, Custom)

### Data Quality
- **IOC Coverage**: High (74,546 IOCs from Abuse.ch)
- **Relationship Coverage**: Medium (limited to OTX pulse data)
- **Threat Actor Coverage**: Low (4 threat actors)
- **Campaign Coverage**: Low (3 campaigns)

### Data Freshness
- **Abuse.ch**: Real-time updates
- **OTX**: 24-hour refresh cycle
- **Manual Data**: Static (test relationships)

## API Integration

### FastAPI Endpoints

#### IOC Endpoints
- `GET /api/v1/iocs` - List IOCs with filtering
- `GET /api/v1/iocs/{ioc_id}` - Get specific IOC
- `GET /api/v1/iocs/{ioc_id}/relationships` - Get IOC relationships
- `POST /api/v1/iocs` - Create new IOC

#### Threat Actor Endpoints
- `GET /api/v1/threat-actors` - List threat actors
- `GET /api/v1/threat-actors/{actor_id}` - Get specific threat actor
- `POST /api/v1/threat-actors` - Create new threat actor

#### Campaign Endpoints
- `GET /api/v1/campaigns` - List campaigns
- `GET /api/v1/campaigns/{campaign_id}` - Get specific campaign
- `POST /api/v1/campaigns` - Create new campaign

#### Graph Endpoints
- `GET /api/v1/graph/export` - Export graph data for GNN training
- `GET /api/v1/graph/stats` - Get graph statistics

#### Admin Endpoints
- `POST /api/v1/admin/ingest-sample-data` - Trigger sample data ingestion
- `GET /api/v1/health` - System health check

### Integration with Existing GNN Project

The system provides data export endpoints specifically designed for integration with the existing GNN attack path project:

```python
# Export graph data for GNN training
GET /api/v1/graph/export?node_types=IOC,ThreatActor&relationship_types=USED_BY,BELONGS_TO
```

This allows the existing GNN system to:
1. Import threat intelligence data
2. Enhance attack path analysis with threat actor context
3. Improve risk scoring with campaign information
4. Correlate IOCs with known threat actors

## Configuration

### Environment Variables
```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# External Threat Feeds
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your_misp_api_key
OTX_API_KEY=your_otx_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
THREAT_FEEDS_API_KEY=your_custom_api_key

# Kafka Configuration
KAFKA_BROKERS=localhost:9092
KAFKA_TOPIC_THREAT_INTEL=threat_intelligence
KAFKA_TOPIC_IOC_CORRELATION=ioc_correlation
```

## Future Enhancements

### Data Source Expansion
1. **STIX/TAXII Integration**: Support for structured threat intelligence
2. **Commercial Feeds**: Integration with commercial threat intelligence providers
3. **Internal Sources**: Organization-specific threat data

### Relationship Enhancement
1. **Automatic Correlation**: ML-based IOC correlation
2. **Temporal Relationships**: Time-based threat actor evolution
3. **Geographic Relationships**: Location-based threat analysis

### Processing Improvements
1. **Real-time Processing**: Stream processing for immediate threat updates
2. **Data Quality**: Automated data validation and enrichment
3. **Performance**: Optimized queries and indexing

## Monitoring and Maintenance

### Health Checks
- Neo4j connection status
- Kafka broker connectivity
- External API availability
- Data freshness monitoring

### Logging
- Structured logging with `structlog`
- Threat feed ingestion logs
- Error tracking and alerting
- Performance metrics

### Backup and Recovery
- Neo4j database backups
- Kafka topic retention policies
- Configuration backup
- Disaster recovery procedures

## Quick Reference

### Key Commands

#### Start Services
```bash
# Start Docker services (Neo4j, Kafka, API)
docker-compose -f docker/docker-compose.yml up -d

# Initialize database schema
python scripts/init_database.py

# Ingest sample data
curl -X POST http://localhost:8000/api/v1/admin/ingest-sample-data
```

#### Check Data Status
```bash
# Check Neo4j data
python -c "
from database.neo4j.connection import execute_query
result = execute_query('MATCH (n) RETURN labels(n)[0] as label, count(n) as count ORDER BY count DESC')
for r in result: print(f'{r[\"label\"]}: {r[\"count\"]:,}')
"
```

#### Test API Endpoints
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Get IOCs
curl http://localhost:8000/api/v1/iocs?limit=10

# Get threat actors
curl http://localhost:8000/api/v1/threat-actors

# Export graph data
curl http://localhost:8000/api/v1/graph/export
```

### Configuration Files

#### Environment Variables (.env)
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
OTX_API_KEY=your_otx_key
VIRUSTOTAL_API_KEY=your_vt_key
KAFKA_BROKERS=localhost:9092
```

#### Key Directories
```
├── data/ingestion/          # Feed ingestion services
├── streaming/               # Kafka producer/consumer
├── database/neo4j/          # Neo4j connection & schemas
├── api/                     # FastAPI application
├── config/                  # Configuration management
└── docs/                    # Documentation
```

### Common Queries

#### Neo4j Cypher Queries
```cypher
-- Get all IOC types and counts
MATCH (ioc:IOC) RETURN ioc.type, count(ioc) ORDER BY count(ioc) DESC

-- Find IOCs used by specific threat actor
MATCH (ioc:IOC)-[:USED_BY]->(ta:ThreatActor {name: "Lazarus Group"})
RETURN ioc.value, ioc.type

-- Get threat actors and their campaigns
MATCH (ta:ThreatActor)-[:BELONGS_TO]->(c:Campaign)
RETURN ta.name, c.name

-- Find assets exposed to IOCs
MATCH (a:Asset)-[:EXPOSED_TO]->(ioc:IOC)
RETURN a.name, ioc.value, ioc.type
```

#### API Queries
```bash
# Search IOCs by type
curl "http://localhost:8000/api/v1/iocs?type=domain&limit=5"

# Get IOC relationships
curl "http://localhost:8000/api/v1/iocs/{ioc_id}/relationships?depth=2"

# Export specific node types
curl "http://localhost:8000/api/v1/graph/export?node_types=IOC,ThreatActor"
```

### Troubleshooting

#### Common Issues
1. **Neo4j Connection Failed**: Check if Neo4j is running and credentials are correct
2. **Kafka Connection Error**: Ensure Kafka is running on localhost:9092
3. **API Key Issues**: Verify API keys in .env file are valid and have proper permissions
4. **Empty Graph**: Run sample data ingestion to populate initial data

#### Logs Location
- **Application Logs**: Console output with structured logging
- **Neo4j Logs**: Docker container logs
- **Kafka Logs**: Kafka container logs

#### Health Checks
```bash
# Check Neo4j
curl http://localhost:7474/browser/

# Check Kafka
curl http://localhost:8080

# Check API
curl http://localhost:8000/api/v1/health
```

---

*Last Updated: October 4, 2025*
*Version: 1.0*
