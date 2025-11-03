#!/usr/bin/env python3
"""
Test if the BLOB_READ_WRITE_TOKEN is configured on the deployed API
"""
import requests

def test_api_blob_config():
    """Test if the API has the blob token configured"""
    
    # Create a simple test endpoint check
    test_url = "https://kinjar-api.fly.dev/media/upload"
    
    # Try to upload a test file - the response will tell us if blob is configured
    test_content = b"Test"
    files = {
        'file': ('test.jpg', test_content, 'image/jpeg')
    }
    
    print("🧪 Testing if BLOB_READ_WRITE_TOKEN is configured on deployed API...")
    
    try:
        response = requests.post(test_url, files=files)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            url = data.get('url', '')
            print(f"Response URL: {url}")
            
            if 'blob.vercel-storage.com' in url or 'vercel-storage.com' in url:
                print("✅ Real Vercel Blob storage is working!")
                return True
            elif 'kinjar-api.fly.dev' in url:
                print("⚠️  Still using mock URLs - BLOB_READ_WRITE_TOKEN may not be configured")
                return False
            else:
                print(f"❓ Unknown URL format: {url}")
                return False
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    test_api_blob_config()