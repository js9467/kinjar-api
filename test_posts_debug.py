#!/usr/bin/env python3
"""
Test script to debug the posts endpoint issue
"""

import requests
import json

def test_family_posts():
    """Test the family posts endpoint"""
    url = "https://kinjar-api.fly.dev/api/families/slaughterbeck/posts"
    
    try:
        print(f"Testing: {url}")
        
        response = requests.get(url, headers={
            "Content-Type": "application/json",
            "Origin": "https://kinjar.com"
        })
        
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Data: {json.dumps(data, indent=2)}")
        
    except Exception as e:
        print(f"Error: {e}")

def test_family_details():
    """Test the family details endpoint for comparison"""
    url = "https://kinjar-api.fly.dev/api/families/slaughterbeck"
    
    try:
        print(f"\nTesting: {url}")
        
        response = requests.get(url, headers={
            "Content-Type": "application/json",
            "Origin": "https://kinjar.com"
        })
        
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Response: {response.text}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_family_details()
    test_family_posts()