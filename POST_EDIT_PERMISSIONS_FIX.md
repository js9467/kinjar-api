# Post Edit Permissions Fix - "Post as Child" Feature

## Issue Identified
Users with ADULT role could not edit posts they created on behalf of children using the "post as child" feature, even though they should have permission to edit those posts.

## Root Cause Analysis
From debugging logs, the permission issue was clear:

**Your Account:**
- User ID: `b88af6a7-bfe4-4638-94c3-9476aa9d1bcf` 
- Role: `ADULT`

**Posts You're Trying to Edit:**
- Post Author ID: `698a5835-1385-4a7c-a37a-0aa99ef94d41` (child member)
- Author Role: Child (CHILD_5_10, etc.)

**Previous Permission Logic:**
Only allowed editing if:
1. User is the post author (`post.author_id == user.id`) OR
2. User has ADMIN/OWNER role

**The Problem:**
When you use "post as child" feature, the post gets `author_id` set to the child's ID, but you (the adult) created it. The old logic didn't recognize that adults should be able to edit posts they created on behalf of children.

## Solution Implemented
Enhanced the edit permission logic to allow editing if:

1. ✅ User is the post author (existing logic)
2. ✅ User has ADMIN/OWNER role (existing logic)  
3. ✅ **NEW:** User is ADULT and post author is a child in same family

## Technical Implementation
```python
# New permission logic in edit_post endpoint:
has_adult_child_permission = False
if membership and membership["role"] == "ADULT":
    # Check if the post author is a child in the same family
    cur.execute(
        "SELECT role FROM tenant_users WHERE tenant_id = %s AND user_id = %s",
        (post["tenant_id"], post["author_id"])
    )
    author_membership = cur.fetchone()
    if author_membership and author_membership["role"].startswith("CHILD"):
        has_adult_child_permission = True
```

## Security Considerations
- ✅ Adults can only edit child posts, not other adult posts
- ✅ Must be in the same family (tenant_id check)
- ✅ Only works for roles starting with "CHILD" 
- ✅ Maintains all existing admin/owner permissions
- ✅ Users can still only edit their own posts when they are the author

## Expected Results
After deployment (2-3 minutes):
- ✅ Adults can edit posts they created on behalf of children
- ✅ Adults cannot edit posts by other adults
- ✅ Children can edit their own posts (if they created them directly)
- ✅ Admins/Owners can edit any posts (unchanged)

## Test Cases
1. **Adult editing child post** → ✅ Should work now
2. **Adult editing another adult's post** → ❌ Should be denied  
3. **Admin editing any post** → ✅ Should work (unchanged)
4. **User editing their own post** → ✅ Should work (unchanged)

---
**Deployed:** 2025-11-04  
**Commit:** d84dbb5 - "Fix edit post permissions for 'post as child' feature"