# Post Edit/Delete Permissions Fix

## Issue Summary
Children could edit or delete other children's posts when acting as a child profile. Adults could delete other adults' posts. This was a critical security issue.

## Root Causes

### Frontend Issue
The API client was sending `x-acting-as-child: 'true'` but not including the **child ID** in the request headers. The backend needs to know which specific child the user is acting as.

### Backend Issues
1. **Missing posted_as_id in queries**: Both `delete_post` and `edit_post` didn't fetch the `posted_as_id` column from posts
2. **No posted_as context checking**: Neither endpoint checked the request's `x-posted-as-id` header
3. **Insufficient permission logic**: The simple `author_id == user_id` check didn't account for:
   - When a parent posts as different children (different `posted_as_id` values)
   - When one child tries to edit another child's post
   - When adults try to edit other adults' posts

## Changes Made

### Frontend (kinjar frontend 2.0/src/lib/api.ts)
**Line 229-233**: Added child ID to request headers
```typescript
// Before:
if (this._actingAsChild) {
  headers['x-acting-as-child'] = 'true';
}

// After:
if (this._actingAsChild) {
  headers['x-acting-as-child'] = 'true';
  headers['x-posted-as-id'] = this._actingAsChild.id;  // NEW: Send child ID
  console.log(`[API Request] Setting x-acting-as-child header for: ${this._actingAsChild.name} (ID: ${this._actingAsChild.id})`);
}
```

### Backend (kinjar-api/app.py)

#### delete_post Function

**Line 4862**: Added `posted_as_id` to SELECT query
```python
# Before:
SELECT p.id, p.tenant_id, p.author_id, p.media_id, t.slug AS tenant_slug

# After:
SELECT p.id, p.tenant_id, p.author_id, p.posted_as_id, p.media_id, t.slug AS tenant_slug
```

**Lines 4887-4896**: Added posted_as context checking
```python
# Get the current request's posted_as context (when user is acting as a child)
request_posted_as_id = request.headers.get('x-posted-as-id')

is_author = post["author_id"] == user["id"]

# For children acting as children, check if they're acting as the same child who created the post
is_same_child_author = False
if request_posted_as_id and post["posted_as_id"]:
    is_same_child_author = request_posted_as_id == post["posted_as_id"]
    log.info(f"Delete permission check - Posted as ID match: request={request_posted_as_id}, post={post['posted_as_id']}, match={is_same_child_author}")
```

**Lines 4907-4936**: Enhanced permission logic
```python
if user_role and user_role.startswith("CHILD"):
    # Children can only delete posts they created themselves
    # Must match both: logged-in user is author AND posted_as matches (if applicable)
    if is_author:
        if post["posted_as_id"]:
            # Post was made as a child - must match the posted_as_id
            has_delete_permission = is_same_child_author
            if has_delete_permission:
                log.info(f"Delete permission - Child can delete own post (posted_as matches)")
            else:
                log.info(f"Delete permission - Child cannot delete - posted_as_id mismatch")
        else:
            # Post was made by child but not as another child (shouldn't happen, but allow)
            has_delete_permission = True
            log.info(f"Delete permission - Child can delete own post (no posted_as)")
    else:
        log.info(f"Delete permission - Child cannot delete other's posts")
elif is_author and not post.get("posted_as_id"):
    # User (adult/admin) deleting their own post (not posted as child)
    has_delete_permission = True
    log.info(f"Delete permission - User is author, can delete own post")
```

#### edit_post Function

**Line 5023**: Added `posted_as_id` to SELECT query
```python
# Before:
SELECT p.id, p.tenant_id, p.author_id, p.content, t.slug AS tenant_slug

# After:
SELECT p.id, p.tenant_id, p.author_id, p.posted_as_id, p.content, t.slug AS tenant_slug
```

**Lines 5044-5056**: Added posted_as context checking (same as delete)

**Lines 5067-5095**: Enhanced permission logic (same pattern as delete)

## New Permission Rules

### For Children (CHILD, CHILD_1, CHILD_2, etc.)
- ✅ Can edit/delete their own posts ONLY if:
  - They are the author (author_id matches)
  - AND the posted_as_id matches their current acting-as context
- ❌ Cannot edit/delete posts by other children
- ❌ Cannot edit/delete posts by adults

### For Adults (ADULT)
- ✅ Can edit/delete their own posts (where they are the author)
- ✅ Can edit/delete posts by children in their family
- ❌ Cannot edit/delete posts by other adults

### For Admins/Owners (ADMIN, OWNER)
- ✅ Can edit/delete posts by children in their family (even on connected families)
- ✅ Can edit/delete their own posts
- ✅ Can delete any post in their own family
- ❌ Cannot delete adult posts on connected families

## Testing Scenarios

### Scenario 1: Child Acting as Self
- Parent logs in as "Child A"
- Child A creates a post → posted_as_id = Child A's ID
- Child A can edit/delete this post ✅
- Parent switches to "Child B"
- Child B cannot edit/delete Child A's post ❌

### Scenario 2: Adult Editing Posts
- Adult creates their own post (no posted_as_id)
- Adult can edit/delete their own post ✅
- Adult creates post as "Child A" → posted_as_id = Child A's ID
- Adult can edit/delete this post ✅
- Another adult cannot edit the first adult's personal posts ❌

### Scenario 3: Cross-Family Permissions
- Family A posts on connected Family B's feed
- Family A's children posts are editable by Family A adults ✅
- Family B adults cannot edit Family A adults' posts ❌

## Deployment
```powershell
cd "d:\Software\Kinjar API\kinjar-api"
fly deploy
```

## Verification Steps
1. Log in as adult with multiple children
2. Create post as Child 1
3. Switch to Child 2
4. Verify Child 2 cannot edit/delete Child 1's post
5. Create post as adult
6. Verify other adults cannot edit this post
7. Verify adult can edit their own posts and children's posts

## Files Modified
- `d:\Software\kinjar frontend 2.0\src\lib\api.ts` (1 change)
- `d:\Software\Kinjar API\kinjar-api\app.py` (6 changes across delete_post and edit_post functions)
