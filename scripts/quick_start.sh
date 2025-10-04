#!/bin/bash
# Quick start script for Threat Intelligence Graph

set -e

echo "🕵️  Threat Intelligence Graph - Quick Start"
echo "============================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✅ Docker is running"

# Start services
echo "🚀 Starting Neo4j and API services..."
docker-compose -f docker/docker-compose.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Initialize database
echo "🗄️  Initializing Neo4j database schema..."
python scripts/init_database.py

# Start API server in background
echo "🌐 Starting API server..."
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 &
API_PID=$!

# Wait for API to be ready
echo "⏳ Waiting for API to be ready..."
sleep 5

# Test API health
echo "🔍 Testing API health..."
if curl -s http://localhost:8000/api/v1/health > /dev/null; then
    echo "✅ API is healthy"
else
    echo "❌ API health check failed"
    kill $API_PID 2>/dev/null || true
    exit 1
fi

# Ingest sample data
echo "📊 Ingesting sample threat intelligence data..."
curl -s -X POST http://localhost:8000/api/v1/admin/ingest-sample-data > /dev/null
echo "✅ Sample data ingested"

# Test data population
echo "🔍 Verifying data population..."
RESPONSE=$(curl -s "http://localhost:8000/api/v1/iocs/search?query=malicious")
if echo "$RESPONSE" | grep -q "malicious-sample.com"; then
    echo "✅ Threat intelligence data successfully populated!"
else
    echo "⚠️  Data population may have failed - check API logs"
fi

echo ""
echo "🎉 Threat Intelligence Graph is ready!"
echo ""
echo "📋 Quick Commands:"
echo "  Health Check: curl http://localhost:8000/api/v1/health"
echo "  Search IOCs:  curl 'http://localhost:8000/api/v1/iocs/search?query=malicious'"
echo "  Graph Export: curl http://localhost:8000/api/v1/graph/export"
echo ""
echo "🔗 API Documentation: http://localhost:8000/docs"
echo "🗄️  Neo4j Browser: http://localhost:7474 (neo4j/password)"
echo ""
echo "🛑 To stop services:"
echo "  kill $API_PID"
echo "  docker-compose -f docker/docker-compose.yml down"
echo ""
echo "📖 For more information, see README.md"
