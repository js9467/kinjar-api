#!/usr/bin/env python3
"""
Test Vercel Blob integration directly
"""
import requests
import sys

def test_vercel_blob_direct():
    """Test Vercel Blob API directly"""
    token = "vercel_blob_rw_ZHcVEZkPvrrn4k2C_Pinuk0x4wXUGhwjGPq1MLuwG4DGXli"
    
    # Test file content
    test_content = b"Test image content for Vercel Blob"
    filename = "test-direct.jpg"
    
    # Correct Vercel Blob upload endpoint format
    upload_url = f"https://blob.vercel-storage.com/{filename}"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Content-Type': 'image/jpeg',
    }
    
    print(f"🧪 Testing Vercel Blob API directly...")
    print(f"URL: {upload_url}")
    print(f"Token: {token[:20]}...")
    
    try:
        # Use PUT request with direct file upload
        response = requests.put(upload_url, data=test_content, headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response: {response.text}")
        
        if response.status_code in [200, 201]:
            print(f"✅ Vercel Blob upload successful!")
            print(f"URL: {upload_url}")
            return True
        else:
            print(f"❌ Vercel Blob upload failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    success = test_vercel_blob_direct()
    sys.exit(0 if success else 1)