# Database Table Name Fix - Post Edit Functionality

## Issue Identified
After successfully fixing the CORS issue, post editing was still failing with a 500 Internal Server Error:

```
500 (Internal Server Error)
{details: 'relation "tenant_members" does not exist\nLINE 2:  …                                                ^', error: 'edit_failed', ok: false}
```

## Root Cause
The edit post endpoint (`@app.patch("/api/posts/<post_id>")`) was trying to query a table called `tenant_members` to check user permissions, but this table doesn't exist in the database. 

Throughout the rest of the codebase, the correct table name is `tenant_users`.

## Fix Applied
**File:** `app.py`  
**Line:** 4343  
**Change:** Updated table name from `tenant_members` to `tenant_users`

```sql
-- BEFORE (incorrect):
SELECT role FROM tenant_members
WHERE tenant_id = %s AND user_id = %s

-- AFTER (correct):
SELECT role FROM tenant_users  
WHERE tenant_id = %s AND user_id = %s
```

## Verification
- Fix deployed via git push to kinjar-api repository
- Backend will automatically redeploy (2-3 minutes)
- Post editing should now work without database errors

## Expected Result
After deployment completes:
1. ✅ CORS errors resolved (previous fix)
2. ✅ Database table errors resolved (this fix)  
3. ✅ Post editing functionality fully working
4. ✅ User permission checks working correctly

## Testing Steps
1. Wait for backend deployment to complete
2. Try editing a post on slaughterbeck.kinjar.com
3. Verify no console errors appear
4. Confirm post content updates successfully

---
**Deployed:** 2025-11-04  
**Commit:** c527a81 - "Fix database table name in edit post endpoint"