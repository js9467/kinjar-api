#!/usr/bin/env python3
"""
Diagnostic script for media endpoint 502 errors
"""

import requests
import json
import sys

def test_media_endpoints():
    """Test various media-related endpoints"""
    print("🔍 Diagnosing Media Endpoint Issues")
    print("=" * 50)
    
    base_url = "https://kinjar-api.fly.dev"
    
    # Test the specific media files mentioned in the error
    media_files = [
        "dfc476d4-cd67-41d5-a2fe-f62fddce3346",
        "b53b6d64-1fb1-43c9-b7f1-602f99e2e267", 
        "27a4a4ab-0444-4e82-a05b-ef7bcb38b75f"
    ]
    
    print("\n1. Testing specific media files from error...")
    for media_id in media_files:
        url = f"{base_url}/api/media/{media_id}"
        try:
            response = requests.get(url, timeout=10)
            print(f"   📁 {media_id}: Status {response.status_code}")
            if response.status_code != 200:
                print(f"      Response: {response.text[:100]}...")
        except Exception as e:
            print(f"   ❌ {media_id}: Error - {e}")
    
    print("\n2. Testing media endpoint with HEAD request...")
    try:
        response = requests.head(f"{base_url}/api/media/test", timeout=10)
        print(f"   HEAD /api/media/test: Status {response.status_code}")
    except Exception as e:
        print(f"   ❌ HEAD request failed: {e}")
    
    print("\n3. Testing if it's a Next.js image optimization issue...")
    print("   The error URL pattern suggests Next.js is trying to optimize images:")
    print("   https://slaughterbeck.kinjar.com/_next/image?url=https%3A%2F%2Fkinjar-api.fly.dev%2Fapi%2Fmedia%2F...")
    print("   This indicates the frontend is successfully calling the backend, but Next.js optimization is failing.")
    
    print("\n4. Testing backend connectivity...")
    try:
        response = requests.get(f"{base_url}/health", timeout=10)
        if response.status_code == 200:
            print(f"   ✅ Backend health check: OK")
        else:
            print(f"   ⚠️  Backend health check: Status {response.status_code}")
    except Exception as e:
        print(f"   ❌ Backend unreachable: {e}")
    
    print("\n" + "=" * 50)
    print("📋 Diagnosis Summary:")
    print("   🔍 Problem: 502 Bad Gateway errors for Next.js image optimization")
    print("   🎯 Root Cause: Likely one of the following:")
    print("      • Media files are corrupted or missing")
    print("      • Backend timeout during image serving")
    print("      • Next.js image optimization configuration issue")
    print("      • Network connectivity issue between Next.js and backend")
    
    print("\n💡 Recommended Solutions:")
    print("   1. Check if media files exist in the backend database")
    print("   2. Verify media file storage (Vercel Blob) is accessible") 
    print("   3. Consider adding Next.js image optimization timeout")
    print("   4. Add error handling for missing media files")
    print("   5. Check if the issue is temporary (refresh the page)")

if __name__ == "__main__":
    test_media_endpoints()