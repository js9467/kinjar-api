# Family Connections Fix - November 4, 2025

## Problem
The family connections feature was throwing a 500 error when trying to load connections:
```
Failed to load resource: the server responded with a status of 500 ()
[API Error] 500 : Object
Failed to load connections: Error: HTTP 500
```

However, the search families feature was working correctly, showing all families.

## Root Cause Analysis
The issue was in the `/api/families/connections` endpoint in `app.py` at line 5062-5063.

The SQL query was using incorrect type casting in the JOIN conditions:
```sql
LEFT JOIN user_profiles requester_profile ON requester.id::text = requester_profile.user_id
LEFT JOIN user_profiles responder_profile ON responder.id::text = responder_profile.user_id
```

The problem:
- `users.id` is type `UUID`
- `user_profiles.user_id` is type `UUID` (as defined in the schema at line 467)
- The query was casting `requester.id` to `text` before comparing, causing a type mismatch
- PostgreSQL cannot efficiently join text to UUID types, resulting in a 500 error

## Solution
Changed the JOIN conditions to compare UUID to UUID directly without casting:
```sql
LEFT JOIN user_profiles requester_profile ON requester.id = requester_profile.user_id
LEFT JOIN user_profiles responder_profile ON responder.id = responder_profile.user_id
```

## Files Modified
- `d:\Software\Kinjar API\kinjar-api\app.py` - Lines 5062-5063

## Deployment
- Fix deployed to Fly.io: `kinjar-api.fly.dev`
- Deployment ID: `01K98XB9H2970V2GYH7A40GF5F`
- Image size: 97 MB

## Testing
The fix allows the `/api/families/connections` endpoint to:
1. Successfully query family connections for the current tenant
2. Return both incoming and outgoing connection requests
3. Include user profile information (display names) from the user_profiles table
4. Handle cases where users may not have profiles (LEFT JOIN)

## Expected Behavior After Fix
- Family connections page loads without 500 errors
- Users can view their family's connection requests (incoming and outgoing)
- Users can search for other families (this was already working)
- Users can accept/decline connection requests
- Connection status is properly displayed for each family
