# GNN Integration Guide
## Threat Intelligence Graph API for Graph Neural Networks

This guide shows how your GNN project can connect to and consume data from the Threat Intelligence Graph API.

## Quick Start

```python
import httpx
import networkx as nx
from typing import Dict, List

class ThreatIntelligenceClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
    
    async def get_asset_threat_context(self, asset_id: str) -> Dict:
        """Get threat intelligence context for a specific asset"""
        response = await self.client.get(f"{self.base_url}/api/v1/iocs/asset/{asset_id}")
        return response.json()
    
    async def get_threat_relationships(self, ioc_id: str, depth: int = 2) -> List[Dict]:
        """Get relationship data for graph-based analysis"""
        response = await self.client.get(f"{self.base_url}/api/v1/iocs/{ioc_id}/relationships")
        return response.json()
    
    async def build_threat_graph(self, seed_iocs: List[str]) -> nx.Graph:
        """Build a NetworkX graph from threat intelligence data"""
        graph = nx.Graph()
        
        for ioc_id in seed_iocs:
            relationships = await self.get_threat_relationships(ioc_id)
            for rel in relationships:
                graph.add_edge(rel['source'], rel['target'], **rel['properties'])
        
        return graph
```

## API Endpoints & Data Formats

### 1. Asset Threat Context
**Endpoint:** `GET /api/v1/iocs/asset/{asset_id}`

**Purpose:** Get all threat intelligence related to a specific asset

**Example Request:**
```bash
curl "http://localhost:8000/api/v1/iocs/asset/server-001"
```

**Response Format:**
```json
{
  "asset_id": "server-001",
  "threat_level": "high",
  "confidence": 0.85,
  "threat_actors": ["APT29", "Cozy Bear"],
  "campaigns": ["SolarWinds Campaign"],
  "ttps": ["T1055", "T1071"],
  "iocs": [
    {
      "id": "ioc_001",
      "type": "ip_address",
      "value": "192.168.1.100",
      "category": "malicious",
      "confidence": 0.9,
      "first_seen": "2024-01-15T10:30:00Z",
      "last_seen": "2024-01-20T14:45:00Z",
      "source": "OTX",
      "description": "Suspicious IP address",
      "context": {"campaign": "SolarWinds"}
    }
  ]
}
```

### 2. IOC Relationships (Graph Building)
**Endpoint:** `GET /api/v1/iocs/{ioc_id}/relationships?depth=2`

**Purpose:** Get relationship data for building graph structures

**Example Request:**
```bash
curl "http://localhost:8000/api/v1/iocs/ioc_001/relationships?depth=3"
```

**Response Format:**
```json
{
  "ioc_id": "ioc_001",
  "depth": 3,
  "count": 15,
  "relationships": [
    {
      "source": "ioc_001",
      "target": "ta_001",
      "source_type": "IOC",
      "target_type": "ThreatActor",
      "relationships": [
        {
          "type": "USED_BY",
          "properties": {"confidence": 0.9, "first_seen": "2024-01-15T10:30:00Z"}
        }
      ],
      "path_length": 1,
      "properties": {
        "source_properties": {
          "id": "ioc_001",
          "type": "ip_address",
          "value": "192.168.1.100",
          "confidence": 0.9
        },
        "target_properties": {
          "id": "ta_001",
          "name": "APT29",
          "country": "Russia",
          "motivation": "Espionage"
        }
      }
    },
    {
      "source": "ioc_001",
      "target": "campaign_001",
      "source_type": "IOC",
      "target_type": "Campaign",
      "relationships": [
        {
          "type": "INVOLVES",
          "properties": {"confidence": 0.85}
        }
      ],
      "path_length": 1,
      "properties": {
        "source_properties": {"id": "ioc_001", "value": "192.168.1.100"},
        "target_properties": {"id": "campaign_001", "name": "SolarWinds Campaign"}
      }
    }
  ]
}
```

### 3. Full Graph Export (GNN Training)
**Endpoint:** `GET /api/v1/graph/export?node_types=IOC,ThreatActor,Asset&relationship_types=USED_BY,INVOLVES`

**Purpose:** Export complete graph for GNN model training

**Example Request:**
```bash
curl "http://localhost:8000/api/v1/graph/export?node_types=IOC,ThreatActor,Asset"
```

**Response Format:**
```json
{
  "nodes": [
    {
      "id": "ioc_001",
      "type": "ip_address",
      "value": "192.168.1.100",
      "confidence": 0.9,
      "category": "malicious"
    },
    {
      "id": "ta_001",
      "name": "APT29",
      "country": "Russia",
      "motivation": "Espionage",
      "status": "active"
    },
    {
      "id": "asset_001",
      "type": "server",
      "environment": "production",
      "criticality": "high"
    }
  ],
  "relationships": [
    {
      "source": "ioc_001",
      "target": "ta_001",
      "type": "USED_BY",
      "properties": {"confidence": 0.9}
    },
    {
      "source": "ioc_001",
      "target": "asset_001",
      "type": "OBSERVED_ON",
      "properties": {"timestamp": "2024-01-15T10:30:00Z"}
    }
  ],
  "node_count": 1250,
  "relationship_count": 3400,
  "export_timestamp": "2024-01-20T15:30:00Z"
}
```

### 4. Risk Score Enhancement
**Endpoint:** `GET /api/v1/enhance/risk-score?asset_id=server-001&base_risk_score=0.7`

**Purpose:** Enhance GNN risk scores with threat intelligence context

**Example Request:**
```bash
curl "http://localhost:8000/api/v1/enhance/risk-score?asset_id=server-001&base_risk_score=0.7"
```

**Response Format:**
```json
{
  "asset_id": "server-001",
  "base_risk_score": 0.7,
  "threat_level": "high",
  "threat_multiplier": 1.6,
  "enhanced_risk_score": 0.85,
  "threat_context": {
    "asset_id": "server-001",
    "threat_level": "high",
    "confidence": 0.85,
    "threat_actors": ["APT29"],
    "iocs": [...],
    "campaigns": ["SolarWinds Campaign"],
    "ttps": ["T1055", "T1071"]
  },
  "timestamp": "2024-01-20T15:30:00Z"
}
```

## Data Model Overview

### Node Types Available:
- **IOC** (Indicators of Compromise): IPs, domains, file hashes, etc.
- **ThreatActor**: Known threat groups and individuals
- **Campaign**: Organized threat campaigns
- **Asset**: Internal infrastructure assets
- **Malware**: Malware families and samples
- **TTP** (Tactics, Techniques, Procedures): MITRE ATT&CK techniques
- **Vulnerability**: CVE vulnerabilities
- **Organization**: Targeted organizations

### Relationship Types:
- **USED_BY**: ThreatActor uses IOC/TTP/Malware
- **INVOLVES**: Campaign involves IOC/ThreatActor
- **TARGETS**: ThreatActor/Campaign targets Asset/Organization
- **OBSERVED_ON**: IOC observed on Asset
- **EXPOSED_TO**: Asset exposed to IOC
- **ASSOCIATED_WITH**: IOC associated with Malware
- **EXPLOITS**: TTP exploits Vulnerability

## Integration Patterns

### Pattern 1: Real-time Threat Context
```python
async def analyze_asset_risk(asset_id: str, gnn_risk_score: float):
    """Enhance GNN risk score with threat intelligence"""
    client = ThreatIntelligenceClient()
    
    # Get threat context
    threat_context = await client.get_asset_threat_context(asset_id)
    
    # Enhance risk score
    enhanced_risk = await client.enhance_risk_score(asset_id, gnn_risk_score)
    
    return enhanced_risk
```

### Pattern 2: Graph-based Analysis
```python
async def build_attack_graph(seed_assets: List[str]):
    """Build attack graph from seed assets"""
    client = ThreatIntelligenceClient()
    graph = nx.DiGraph()
    
    for asset_id in seed_assets:
        # Get threat context
        context = await client.get_asset_threat_context(asset_id)
        
        # Add asset to graph
        graph.add_node(asset_id, node_type="Asset", **context)
        
        # Add related IOCs and their relationships
        for ioc in context['iocs']:
            relationships = await client.get_threat_relationships(ioc['id'])
            for rel in relationships:
                graph.add_edge(
                    rel['source'], 
                    rel['target'],
                    edge_type=rel['relationships'][0]['type'],
                    **rel['properties']
                )
    
    return graph
```

### Pattern 3: GNN Training Data
```python
async def prepare_training_data():
    """Export data for GNN model training"""
    client = ThreatIntelligenceClient()
    
    # Export full graph
    graph_data = await client.export_full_graph(
        node_types=["IOC", "ThreatActor", "Asset", "Campaign"]
    )
    
    # Convert to PyTorch Geometric format
    import torch_geometric as pyg
    
    # Extract node features
    node_features = []
    node_mapping = {}
    for i, node in enumerate(graph_data['nodes']):
        node_mapping[node['id']] = i
        features = [
            node.get('confidence', 0.0),
            node.get('criticality_score', 0.0),
            # Add more features as needed
        ]
        node_features.append(features)
    
    # Extract edges
    edge_index = []
    edge_attr = []
    for rel in graph_data['relationships']:
        source_idx = node_mapping.get(rel['source'])
        target_idx = node_mapping.get(rel['target'])
        if source_idx is not None and target_idx is not None:
            edge_index.append([source_idx, target_idx])
            edge_attr.append([rel['properties'].get('confidence', 0.0)])
    
    return pyg.data.Data(
        x=torch.tensor(node_features),
        edge_index=torch.tensor(edge_index).t().contiguous(),
        edge_attr=torch.tensor(edge_attr)
    )
```

## Connection Requirements

### Prerequisites:
- Python 3.8+
- `httpx` for async HTTP requests
- `networkx` for graph operations
- Your GNN framework (PyTorch Geometric, DGL, etc.)

### Installation:
```bash
pip install httpx networkx
```

### Environment Setup:
```bash
# Set your API endpoint
export THREAT_INTEL_API_URL="http://localhost:8000"

# Or in your code
client = ThreatIntelligenceClient("http://your-api-host:8000")
```

## Error Handling

```python
async def safe_api_call(client: ThreatIntelligenceClient, asset_id: str):
    """Example with proper error handling"""
    try:
        context = await client.get_asset_threat_context(asset_id)
        return context
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print(f"Asset {asset_id} not found")
            return None
        elif e.response.status_code == 500:
            print("Server error, retrying...")
            # Implement retry logic
            return None
        else:
            raise
    except httpx.RequestError as e:
        print(f"Network error: {e}")
        return None
```

## Performance Considerations

- **Batch requests** when possible
- **Cache responses** for frequently accessed data
- **Use pagination** for large datasets
- **Filter by node/relationship types** to reduce data transfer
- **Set appropriate depth limits** for relationship traversal

## Example: Complete GNN Integration

```python
import asyncio
import httpx
import networkx as nx
import torch
import torch_geometric as pyg

class GNNThreatAnalyzer:
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.client = ThreatIntelligenceClient(api_url)
        self.graph = nx.DiGraph()
    
    async def load_threat_data(self, asset_ids: List[str]):
        """Load threat intelligence data for GNN analysis"""
        tasks = []
        for asset_id in asset_ids:
            tasks.append(self._load_asset_data(asset_id))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]
    
    async def _load_asset_data(self, asset_id: str):
        """Load data for a single asset"""
        context = await self.client.get_asset_threat_context(asset_id)
        
        # Add asset to graph
        self.graph.add_node(asset_id, node_type="Asset", **context)
        
        # Load related IOCs and relationships
        for ioc in context.get('iocs', []):
            relationships = await self.client.get_threat_relationships(ioc['id'])
            for rel in relationships:
                self.graph.add_edge(
                    rel['source'], 
                    rel['target'],
                    edge_type=rel['relationships'][0]['type'] if rel['relationships'] else 'unknown',
                    **rel['properties']
                )
        
        return context
    
    def analyze_attack_paths(self, source: str, target: str):
        """Analyze potential attack paths"""
        try:
            path = nx.shortest_path(self.graph, source, target)
            return {
                "path": path,
                "length": len(path) - 1,
                "risk": self._calculate_path_risk(path)
            }
        except nx.NetworkXNoPath:
            return {"path": None, "length": float('inf'), "risk": 0.0}
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for attack path"""
        risk = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i+1])
            risk += edge_data.get('confidence', 0.1)
        return min(risk / (len(path) - 1), 1.0)
    
    async def close(self):
        """Clean up resources"""
        await self.client.close()

# Usage example
async def main():
    analyzer = GNNThreatAnalyzer()
    
    try:
        # Load threat data for analysis
        assets = ["server-001", "database-002", "web-003"]
        threat_data = await analyzer.load_threat_data(assets)
        
        # Analyze attack paths
        attack_path = analyzer.analyze_attack_paths("server-001", "database-002")
        print(f"Attack path risk: {attack_path['risk']}")
        
    finally:
        await analyzer.close()

if __name__ == "__main__":
    asyncio.run(main())
```

This integration provides everything your GNN project needs to consume threat intelligence data and enhance its analysis capabilities!
