# API Testing Guide
## Threat Intelligence Graph API Testing

This guide shows you how to test the Threat Intelligence Graph API endpoints, including the new GNN integration features.

## Prerequisites

1. **Start the API server:**
```bash
# From project root
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

2. **Verify Neo4j is running:**
```bash
# Test Neo4j connection
python -c "from database.neo4j.connection import neo4j_connection; print('Neo4j connected:', neo4j_connection.connect())"
```

3. **Initialize sample data (if needed):**
```bash
python scripts/init_database.py
```

## Testing Methods

### Method 1: Using curl (Command Line)

#### 1. Health Check
```bash
curl -X GET "http://localhost:8000/api/v1/health" \
  -H "accept: application/json"
```

**Expected Response:**
```json
{
  "status": "healthy",
  "service": "threat-intelligence-graph-api",
  "version": "1.0.0",
  "timestamp": "2024-01-20T15:30:00Z",
  "services": {
    "neo4j": "healthy"
  }
}
```

#### 2. Get Asset Threat Context
```bash
curl -X GET "http://localhost:8000/api/v1/iocs/asset/server-001" \
  -H "accept: application/json"
```

#### 3. Search IOCs
```bash
curl -X GET "http://localhost:8000/api/v1/iocs/search?confidence_min=0.8&limit=10" \
  -H "accept: application/json"
```

#### 4. Get IOC Relationships (GNN Integration)
```bash
curl -X GET "http://localhost:8000/api/v1/iocs/ioc_001/relationships?depth=2" \
  -H "accept: application/json"
```

#### 5. Export Graph Data (GNN Integration)
```bash
curl -X GET "http://localhost:8000/api/v1/graph/export?node_types=IOC,ThreatActor,Asset" \
  -H "accept: application/json"
```

#### 6. Enhance Risk Score (GNN Integration)
```bash
curl -X GET "http://localhost:8000/api/v1/enhance/risk-score?asset_id=server-001&base_risk_score=0.7" \
  -H "accept: application/json"
```

#### 7. Search Threat Actors
```bash
curl -X GET "http://localhost:8000/api/v1/threat-actors/search?country=Russia&limit=5" \
  -H "accept: application/json"
```

#### 8. Search Campaigns
```bash
curl -X GET "http://localhost:8000/api/v1/campaigns/search?status=active&limit=5" \
  -H "accept: application/json"
```

### Method 2: Using Python httpx

Create a test script `test_api.py`:

```python
import asyncio
import httpx
import json

class APITester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
    
    async def test_health(self):
        """Test health check endpoint"""
        print("Testing health check...")
        response = await self.client.get(f"{self.base_url}/api/v1/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    
    async def test_asset_threat_context(self, asset_id: str = "server-001"):
        """Test asset threat context endpoint"""
        print(f"\nTesting asset threat context for {asset_id}...")
        response = await self.client.get(f"{self.base_url}/api/v1/iocs/asset/{asset_id}")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Threat Level: {data.get('threat_level', 'unknown')}")
            print(f"IOC Count: {len(data.get('iocs', []))}")
        else:
            print(f"Error: {response.text}")
        return response.status_code == 200
    
    async def test_ioc_relationships(self, ioc_id: str = "ioc_001"):
        """Test IOC relationships endpoint (GNN Integration)"""
        print(f"\nTesting IOC relationships for {ioc_id}...")
        response = await self.client.get(f"{self.base_url}/api/v1/iocs/{ioc_id}/relationships?depth=2")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Relationship Count: {data.get('count', 0)}")
        else:
            print(f"Error: {response.text}")
        return response.status_code == 200
    
    async def test_graph_export(self):
        """Test graph export endpoint (GNN Integration)"""
        print("\nTesting graph export...")
        response = await self.client.get(f"{self.base_url}/api/v1/graph/export?node_types=IOC,ThreatActor")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Nodes: {data.get('node_count', 0)}")
            print(f"Relationships: {data.get('relationship_count', 0)}")
        else:
            print(f"Error: {response.text}")
        return response.status_code == 200
    
    async def test_risk_enhancement(self, asset_id: str = "server-001"):
        """Test risk score enhancement (GNN Integration)"""
        print(f"\nTesting risk enhancement for {asset_id}...")
        response = await self.client.get(
            f"{self.base_url}/api/v1/enhance/risk-score",
            params={"asset_id": asset_id, "base_risk_score": 0.7}
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Base Risk: {data.get('base_risk_score', 0)}")
            print(f"Enhanced Risk: {data.get('enhanced_risk_score', 0)}")
            print(f"Threat Level: {data.get('threat_level', 'unknown')}")
        else:
            print(f"Error: {response.text}")
        return response.status_code == 200
    
    async def test_ioc_search(self):
        """Test IOC search endpoint"""
        print("\nTesting IOC search...")
        response = await self.client.get(
            f"{self.base_url}/api/v1/iocs/search",
            params={"confidence_min": 0.8, "limit": 5}
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Found {len(data.get('iocs', []))} IOCs")
        else:
            print(f"Error: {response.text}")
        return response.status_code == 200
    
    async def run_all_tests(self):
        """Run all API tests"""
        print("=" * 50)
        print("THREAT INTELLIGENCE API TESTS")
        print("=" * 50)
        
        tests = [
            self.test_health(),
            self.test_asset_threat_context(),
            self.test_ioc_relationships(),
            self.test_graph_export(),
            self.test_risk_enhancement(),
            self.test_ioc_search()
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        print("\n" + "=" * 50)
        print("TEST RESULTS SUMMARY")
        print("=" * 50)
        
        test_names = [
            "Health Check",
            "Asset Threat Context", 
            "IOC Relationships",
            "Graph Export",
            "Risk Enhancement",
            "IOC Search"
        ]
        
        passed = 0
        for i, (name, result) in enumerate(zip(test_names, results)):
            if isinstance(result, Exception):
                print(f"❌ {name}: FAILED - {result}")
            elif result:
                print(f"✅ {name}: PASSED")
                passed += 1
            else:
                print(f"❌ {name}: FAILED")
        
        print(f"\nResults: {passed}/{len(tests)} tests passed")
        
        return passed == len(tests)
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()

async def main():
    """Run API tests"""
    tester = APITester()
    
    try:
        success = await tester.run_all_tests()
        if success:
            print("\n🎉 All tests passed! API is working correctly.")
        else:
            print("\n⚠️  Some tests failed. Check the output above.")
    finally:
        await tester.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Method 3: Using FastAPI Interactive Docs

1. **Start the API server:**
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

2. **Open your browser and go to:**
   - **Swagger UI:** http://localhost:8000/docs
   - **ReDoc:** http://localhost:8000/redoc

3. **Test endpoints interactively:**
   - Click on any endpoint
   - Click "Try it out"
   - Enter parameters
   - Click "Execute"
   - View the response

### Method 4: Using pytest (Automated Testing)

Create `tests/test_api_integration.py`:

```python
import pytest
import httpx
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

class TestAPIEndpoints:
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]
        assert "service" in data
        assert "version" in data
    
    def test_asset_threat_context(self):
        """Test asset threat context endpoint"""
        response = client.get("/api/v1/iocs/asset/server-001")
        # Should return 200 or 404 (depending on data)
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            data = response.json()
            assert "asset_id" in data
            assert "threat_level" in data
    
    def test_ioc_relationships(self):
        """Test IOC relationships endpoint (GNN Integration)"""
        response = client.get("/api/v1/iocs/ioc_001/relationships?depth=2")
        # Should return 200 or 404 (depending on data)
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            data = response.json()
            assert "ioc_id" in data
            assert "relationships" in data
    
    def test_graph_export(self):
        """Test graph export endpoint (GNN Integration)"""
        response = client.get("/api/v1/graph/export")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "relationships" in data
        assert "node_count" in data
        assert "relationship_count" in data
    
    def test_risk_enhancement(self):
        """Test risk score enhancement (GNN Integration)"""
        response = client.get("/api/v1/enhance/risk-score?asset_id=server-001&base_risk_score=0.7")
        # Should return 200 or 404 (depending on data)
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            data = response.json()
            assert "asset_id" in data
            assert "base_risk_score" in data
            assert "enhanced_risk_score" in data
    
    def test_ioc_search(self):
        """Test IOC search endpoint"""
        response = client.get("/api/v1/iocs/search?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert "iocs" in data
        assert "total_count" in data
        assert "search_params" in data
```

Run the tests:
```bash
pytest tests/test_api_integration.py -v
```

## Quick Test Commands

### Test All Endpoints at Once
```bash
# Run the Python test script
python test_api.py

# Or run individual curl commands
curl -s "http://localhost:8000/api/v1/health" | jq '.status'
curl -s "http://localhost:8000/api/v1/graph/export" | jq '.node_count'
curl -s "http://localhost:8000/api/v1/iocs/search?limit=1" | jq '.total_count'
```

### Test GNN Integration Endpoints
```bash
# Test relationship traversal
curl -s "http://localhost:8000/api/v1/iocs/ioc_001/relationships?depth=2" | jq '.count'

# Test graph export
curl -s "http://localhost:8000/api/v1/graph/export?node_types=IOC,ThreatActor" | jq '.node_count, .relationship_count'

# Test risk enhancement
curl -s "http://localhost:8000/api/v1/enhance/risk-score?asset_id=server-001&base_risk_score=0.7" | jq '.enhanced_risk_score'
```

## Troubleshooting

### Common Issues:

1. **Connection Refused:**
   ```bash
   # Make sure API server is running
   python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. **Neo4j Connection Failed:**
   ```bash
   # Check Neo4j is running
   docker-compose up neo4j
   # Or start Neo4j manually
   ```

3. **No Data Returned:**
   ```bash
   # Initialize sample data
   python scripts/init_database.py
   ```

4. **404 Errors:**
   - Check if sample data exists
   - Use valid asset/IOC IDs from your database
   - Initialize database with sample data first

### Debug Mode:
```bash
# Start API with debug logging
PYTHONPATH=. python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload --log-level debug
```

## Performance Testing

### Load Testing with curl:
```bash
# Test concurrent requests
for i in {1..10}; do
  curl -s "http://localhost:8000/api/v1/health" &
done
wait
```

### Memory Usage:
```bash
# Monitor API memory usage
ps aux | grep uvicorn
```

This testing guide covers all the ways you can test your API, from simple curl commands to comprehensive automated testing suites!
