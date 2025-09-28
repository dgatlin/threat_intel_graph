#!/usr/bin/env python3
"""Test script for Abuse.ch threat intelligence feeds."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from data.ingestion.abuse_ch_feeds import AbuseChFeedIngestion


async def main():
    """Test Abuse.ch feed ingestion."""
    print("🔍 Testing Abuse.ch Threat Intelligence Feeds...")
    print("=" * 60)
    
    # Initialize the ingestion service
    abuse_ch = AbuseChFeedIngestion()
    
    try:
        # Test all feeds
        print("📡 Fetching data from all Abuse.ch feeds...")
        result = await abuse_ch.ingest_all_feeds()
        
        # Display results
        print(f"\n✅ Success! Retrieved {result['total_count']} IOCs")
        print(f"🕒 Ingestion completed at: {result['ingestion_time']}")
        
        # Show breakdown by feed
        feed_results = result.get('feed_results', {})
        print(f"\n📊 Feed Breakdown:")
        for feed_name, data in feed_results.items():
            if feed_name != 'errors' and isinstance(data, list):
                print(f"  {feed_name.upper()}: {len(data)} IOCs")
        
        # Show errors if any
        if feed_results.get('errors'):
            print(f"\n❌ Errors:")
            for error in feed_results['errors']:
                print(f"  - {error}")
        
        # Show sample data
        if result['total_count'] > 0:
            print(f"\n📋 Sample IOCs:")
            for i, ioc in enumerate(result['iocs'][:5]):
                print(f"  {i+1}. {ioc['type'].upper()}: {ioc['value']} ({ioc['source']})")
            
            if result['total_count'] > 5:
                print(f"  ... and {result['total_count'] - 5} more")
        
        print(f"\n🎯 Total IOCs collected: {result['total_count']}")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
    
    finally:
        await abuse_ch.close()


if __name__ == "__main__":
    asyncio.run(main())
