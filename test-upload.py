#!/usr/bin/env python3
"""
Test script to verify Vercel Blob upload functionality
"""
import requests
import sys
import os

def test_upload():
    # Test the upload endpoint
    api_url = "https://kinjar-api.fly.dev/media/upload"
    
    # Create a small test image file
    test_content = b"Test image content"
    
    files = {
        'file': ('test.jpg', test_content, 'image/jpeg')
    }
    
    print(f"Testing upload to: {api_url}")
    
    try:
        response = requests.post(api_url, files=files)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('ok'):
                print("✅ Upload successful!")
                print(f"URL: {data.get('url')}")
                return True
            else:
                print(f"❌ Upload failed: {data.get('error')}")
                return False
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    success = test_upload()
    sys.exit(0 if success else 1)