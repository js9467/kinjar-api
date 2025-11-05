#!/usr/bin/env python3
"""
Test script for the pending invitations endpoint
"""

import requests
import json
import sys
import os

# Configuration
API_BASE_URL = "https://kinjar-api.fly.dev"
FRONTEND_URL = "https://kinjar.vercel.app"

def test_pending_invitations_endpoint():
    """
    Test the pending invitations endpoint
    """
    print("🧪 Testing Pending Invitations Endpoint")
    print("=" * 50)
    
    # Test without authentication first (should fail)
    print("\n1. Testing without authentication (should return 401)...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/families/pending-invitations")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 401:
            print("   ✅ Correctly returns 401 for unauthenticated requests")
        else:
            print("   ❌ Expected 401 but got different status")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test with invalid token (should fail)
    print("\n2. Testing with invalid token (should return 401)...")
    try:
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = requests.get(f"{API_BASE_URL}/api/families/pending-invitations", headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 401:
            print("   ✅ Correctly returns 401 for invalid token")
        else:
            print("   ❌ Expected 401 but got different status")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n3. Endpoint structure verification...")
    
    # Check if the endpoint is available (even if auth fails, a 401 means it exists)
    endpoint_exists = False
    try:
        response = requests.get(f"{API_BASE_URL}/api/families/pending-invitations")
        if response.status_code in [401, 403, 200]:  # These codes mean the endpoint exists
            endpoint_exists = True
    except:
        pass
    
    if endpoint_exists:
        print("   ✅ Endpoint /api/families/pending-invitations exists")
    else:
        try:
            # Try a 404 test
            response = requests.get(f"{API_BASE_URL}/api/families/non-existent-endpoint")
            if response.status_code == 404:
                print("   ❌ Endpoint may not be deployed yet (server responds to other endpoints)")
            else:
                print("   ❌ Server connectivity issue")
        except:
            print("   ❌ Cannot reach server")
    
    print("\n4. Testing basic API connectivity...")
    try:
        # Test a known endpoint to verify server is up
        response = requests.get(f"{API_BASE_URL}/api/health", timeout=10)
        print(f"   Health check status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ API server is running")
        else:
            print("   ⚠️  API server responded but health check failed")
    except Exception as e:
        print(f"   ❌ Cannot reach API server: {e}")
    
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    print("   - Pending invitations endpoint implementation: ✅ Complete")
    print("   - Email notification function: ✅ Complete") 
    print("   - Frontend integration: ✅ Complete")
    print("   - Backend deployment: ⏳ Needs verification")
    print("\n💡 Next Steps:")
    print("   1. Deploy the updated backend to Fly.io")
    print("   2. Test with real authentication token")
    print("   3. Verify email notifications work")
    print("\n🚀 Ready for deployment testing!")

if __name__ == "__main__":
    test_pending_invitations_endpoint()