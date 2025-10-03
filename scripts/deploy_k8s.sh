#!/bin/bash

# Deploy Threat Intelligence Graph to Kubernetes

set -e

echo "🚀 Deploying Threat Intelligence Graph to Kubernetes..."

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    exit 1
fi

# Check if we can connect to cluster
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi

echo "✅ Kubernetes cluster connection verified"

# Create namespace
echo "📦 Creating namespace..."
kubectl apply -f k8s/namespace.yaml

# Create ConfigMap
echo "⚙️ Creating ConfigMap..."
kubectl apply -f k8s/configmap.yaml

# Create Secret
echo "🔐 Creating Secret..."
kubectl apply -f k8s/secret.yaml

# Create PersistentVolumeClaims
echo "💾 Creating PersistentVolumeClaims..."
kubectl apply -f k8s/pvc.yaml

# Deploy services
echo "🚀 Deploying services..."
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Wait for deployments to be ready
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/neo4j -n threat-intel
kubectl wait --for=condition=available --timeout=300s deployment/zookeeper -n threat-intel
kubectl wait --for=condition=available --timeout=300s deployment/kafka -n threat-intel
kubectl wait --for=condition=available --timeout=300s deployment/threat-intel-api -n threat-intel

# Create Ingress (optional)
echo "🌐 Creating Ingress..."
kubectl apply -f k8s/ingress.yaml

# Show status
echo "📊 Deployment Status:"
kubectl get pods -n threat-intel
kubectl get services -n threat-intel

echo ""
echo "✅ Threat Intelligence Graph deployed successfully!"
echo ""
echo "🔗 Access URLs:"
echo "  API: http://threat-intel.local (or use port-forward)"
echo "  Neo4j Browser: http://neo4j.local (or use port-forward)"
echo ""
echo "📋 Useful commands:"
echo "  kubectl port-forward -n threat-intel svc/threat-intel-service 8000:8000"
echo "  kubectl port-forward -n threat-intel svc/neo4j-service 7474:7474"
echo "  kubectl logs -n threat-intel deployment/threat-intel-api -f"
echo ""
echo "🧪 Test the API:"
echo "  curl http://localhost:8000/api/v1/health"


