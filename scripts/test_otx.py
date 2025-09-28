#!/usr/bin/env python3
"""Test script for OTX feed integration."""

import asyncio
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from data.ingestion.otx_feeds import OTXFeedIngestion
from config.settings import settings


async def test_otx_integration():
    """Test the OTX integration."""
    print("🔍 Testing OTX Integration...")
    print(f"API Key: {settings.otx_api_key[:10]}..." if settings.otx_api_key else "No API key found")
    
    if not settings.otx_api_key or settings.otx_api_key == "your_otx_api_key":
        print("❌ Please set your OTX API key in the .env file")
        print("   Add: OTX_API_KEY=your_otx_api_key_here")
        return
    
    otx = OTXFeedIngestion()
    
    try:
        print("\n📡 Fetching recent threats from OTX...")
        result = await otx.ingest_recent_threats(hours_back=24)
        
        print(f"\n✅ Success! Retrieved:")
        print(f"   📊 Pulses: {len(result.get('pulses', []))}")
        print(f"   🎯 Indicators: {len(result.get('indicators', []))}")
        
        if result.get('pulses'):
            print(f"\n📋 Sample Pulse:")
            pulse = result['pulses'][0]
            print(f"   Name: {pulse.get('name', 'N/A')}")
            print(f"   Author: {pulse.get('author', 'N/A')}")
            print(f"   Tags: {', '.join(pulse.get('tags', []))}")
        
        if result.get('indicators'):
            print(f"\n🎯 Sample Indicators:")
            for i, indicator in enumerate(result['indicators'][:5]):
                print(f"   {i+1}. {indicator.get('type', 'unknown')}: {indicator.get('value', 'N/A')}")
        
        print(f"\n🕒 Ingestion completed at: {result.get('ingestion_time', 'N/A')}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await otx.close()


if __name__ == "__main__":
    asyncio.run(test_otx_integration())
