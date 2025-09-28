# 🚀 OTX Integration Setup Guide

## Quick Start

### 1. Set up your environment
```bash
# Copy the example environment file
cp env.example .env

# Edit .env and add your OTX API key
echo "OTX_API_KEY=your_otx_api_key_here" >> .env
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Test the OTX integration
```bash
python scripts/test_otx.py
```

## What the OTX Integration Does

### 📡 **Data Sources**
- **Pulses**: Threat intelligence reports from the community
- **Indicators**: IOCs (IPs, domains, hashes, URLs, etc.)
- **Malware Families**: Associated malware information
- **Attack Techniques**: MITRE ATT&CK techniques

### 🔄 **Data Flow**
1. **Fetch Recent Pulses** - Gets threat reports from last 24 hours
2. **Extract Indicators** - Pulls IOCs from each pulse
3. **Normalize Data** - Converts to our standard format
4. **Store in Graph** - Saves to Neo4j database

### 📊 **Data Types Retrieved**
- **IP Addresses** (IPv4/IPv6)
- **Domains & Hostnames**
- **URLs**
- **File Hashes** (MD5, SHA1, SHA256, SHA512)
- **Email Addresses**
- **CVE Vulnerabilities**
- **YARA Rules**

## API Rate Limits

- **Free Tier**: 1,000 requests per day
- **Rate Limiting**: Built-in delays to respect limits
- **Error Handling**: Graceful handling of rate limit exceeded

## Next Steps

1. **Test the integration** with the provided script
2. **Set up Kafka** for real-time processing
3. **Configure Neo4j** for data storage
4. **Add more feeds** (MISP, VirusTotal, etc.)

## Troubleshooting

### Common Issues
- **API Key Error**: Make sure your key is correctly set in `.env`
- **Rate Limit**: Wait a few minutes and try again
- **Network Issues**: Check your internet connection

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python scripts/test_otx.py
```

## Integration with GNN Project

The OTX data will be available through:
- **REST API endpoints** for real-time queries
- **Kafka topics** for streaming data
- **Neo4j graph** for complex relationship queries

This provides the threat intelligence data layer that feeds into your GNN Attack Path analysis system.
