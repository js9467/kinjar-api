#!/usr/bin/env python3
"""
Test script to verify comment permission fixes
Run this after deploying the changes to test all permission scenarios
"""

import requests
import json
import sys

BASE_URL = "https://kinjar-api.fly.dev"
FAMILY_SLUG = "slaughterbeck"

# Test scenarios with expected outcomes
TESTS = [
    {
        "name": "Child edits own comment",
        "should_allow": True,
        "description": "A child should be able to edit their own comment"
    },
    {
        "name": "Child edits another child's comment", 
        "should_allow": False,
        "description": "A child should NOT be able to edit another child's comment"
    },
    {
        "name": "Child edits adult's comment",
        "should_allow": False,
        "description": "A child should NOT be able to edit an adult's comment"
    },
    {
        "name": "Adult edits own comment",
        "should_allow": True,
        "description": "An adult should be able to edit their own comment"
    },
    {
        "name": "Adult edits another adult's comment",
        "should_allow": False,
        "description": "An adult should NOT be able to edit another adult's comment"
    },
    {
        "name": "Adult edits child's comment",
        "should_allow": False,
        "description": "An adult should NOT be able to edit a child's own comment"
    },
    {
        "name": "Adult edits comment posted_as their child",
        "should_allow": True,
        "description": "An adult should be able to edit a comment they authored and posted_as their child"
    },
    {
        "name": "Admin edits any comment",
        "should_allow": True,
        "description": "An admin should be able to edit any comment in their family"
    },
]

def print_test_results():
    """Print expected test results"""
    print("=" * 80)
    print("COMMENT PERMISSION TEST SUITE")
    print("=" * 80)
    print("\nExpected Behavior After Fix:\n")
    
    for test in TESTS:
        status = "✅ ALLOW" if test["should_allow"] else "❌ DENY"
        print(f"{status} | {test['name']}")
        print(f"        {test['description']}\n")

def main():
    print_test_results()
    
    print("\n" + "=" * 80)
    print("To run actual API tests:")
    print("=" * 80)
    print("""
1. Ensure the API is deployed with the fixes
2. Get auth tokens for different user roles in the slaughterbeck family:
   - Get a child token
   - Get an adult token
   - Get an admin token

3. Create test comments with different authors/roles

4. For each test case, attempt to edit/delete using the different tokens

5. Verify the response:
   - Expected ALLOW cases should return: {"ok": true, "comment": {...}}
   - Expected DENY cases should return: {"ok": false, "error": "insufficient_permissions"}

Example API call (PATCH - Edit):
    curl -X PATCH \\
      https://kinjar-api.fly.dev/api/comments/{comment_id} \\
      -H "Authorization: Bearer {token}" \\
      -H "x-tenant-slug: slaughterbeck" \\
      -H "Content-Type: application/json" \\
      -d '{"content": "Updated comment"}'

Example API call (DELETE):
    curl -X DELETE \\
      https://kinjar-api.fly.dev/api/comments/{comment_id} \\
      -H "Authorization: Bearer {token}" \\
      -H "x-tenant-slug: slaughterbeck"
    """)

if __name__ == "__main__":
    main()
