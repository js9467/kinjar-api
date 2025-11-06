# Comment Permission System - Fix Applied (Nov 6, 2025)

## Problem Statement
The comment editing and deletion system had insufficient permission checks that allowed:
- Adults to edit/delete other adults' comments
- Children to edit/delete other users' comments

## Requirements
✅ **Children:** Can edit/delete ONLY their own comments
✅ **Adults:** Can edit/delete their own comments AND comments they authored as their children  
✅ **Admins:** Can edit/delete ANY comment in the family

## Root Cause
The original permission logic in both `edit_comment` and `delete_comment_by_uuid` had flawed conditions:

### Original (Buggy) Logic:
```python
elif current_role in ['ADULT', 'MEMBER']:
    if comment['author_id'] == user['id']:
        can_edit = True
    # BUG: This condition allowed ANY adult to edit ANY child's comment
    elif author_role and _is_child_role(author_role):
        can_edit = True  # WRONG - no check that adult is the parent!
```

This was problematic because:
1. It didn't verify the adult was the parent/author of the child account
2. It allowed adults to edit comments authored BY children (not posted_as children)
3. No restriction on editing other adults' comments

### New (Fixed) Logic:
```python
elif current_role in ['ADULT', 'MEMBER']:
    # Only their own comments
    if comment['author_id'] == user['id']:
        can_edit = True
    # Only comments they authored but posted_as a child
    elif (has_posted_as_id and comment.get('posted_as_id') and 
          comment['author_id'] == user['id'] and 
          _is_child_role(posted_as_role)):
        can_edit = True
    else:
        can_edit = False
```

The critical fix: `comment['author_id'] == user['id']` is now required in both conditions, ensuring:
- Adults can only modify comments THEY authored
- If it's posted_as a child, the adult must be the original author

## Changes Applied

### File: `/api/comments/<comment_id>` (PATCH - Edit Endpoint)
**Location:** Lines 5246-5280

**Before:** 15 lines of flawed permission logic allowing adult-to-adult and adult-to-child edits

**After:** 
- Clear, sequential permission checks
- Better logging for debugging
- Explicit denial of inter-adult comment editing
- Proper validation of posted_as scenarios

### File: `/api/comments/<comment_id>` (DELETE Endpoint)  
**Location:** Lines 5405-5439

**Before:** Same 15 lines of flawed logic copied into delete function

**After:** Identical permission structure as edit, ensuring consistency

## Permission Matrix

| User Role | Can Edit/Delete | Comment Details |
|-----------|-----------------|-----------------|
| **ADMIN/OWNER** | ANY comment | Full access in family |
| **ROOT ADMIN** | ANY comment | Global access |
| **ADULT/MEMBER** | Own comments | `author_id == user_id` |
| **ADULT/MEMBER** | Posted_as child | `author_id == user_id AND posted_as_role == CHILD*` |
| **ADULT/MEMBER** | Other adult's comment | ❌ DENIED |
| **ADULT/MEMBER** | Child's own comment | ❌ DENIED |
| **CHILD*** | Own comment | `author_id == user_id` |
| **CHILD*** | Any other comment | ❌ DENIED |

## Testing Checklist

After deployment, verify these scenarios:

```
✅ ALLOW: Child edits own comment
✅ ALLOW: Adult edits own comment  
✅ ALLOW: Adult edits comment posted_as their child
✅ ALLOW: Admin edits any comment

❌ DENY: Child edits another child's comment
❌ DENY: Child edits adult's comment
❌ DENY: Adult edits another adult's comment
❌ DENY: Adult edits child's own comment
```

## API Response Format

**Success (Allowed):**
```json
HTTP 200
{
  "ok": true,
  "comment": {
    "id": "uuid",
    "content": "updated content",
    "created_at": "timestamp",
    "updated_at": "timestamp"
  }
}
```

**Denied:**
```json
HTTP 403
{
  "ok": false,
  "error": "insufficient_permissions"
}
```

## Debugging

Both endpoints now log detailed permission decisions:
- "Adult {user_id} can edit their own comment"
- "Adult {user_id} can edit comment they authored and posted_as child {child_id}"
- "Adult {user_id} cannot edit this comment (author: {author_id}, posted_as: {posted_as_id})"
- "Child {user_id} cannot edit other users' comments"

Check application logs for `Permission check:` or `Edit permission check:` messages.

## Code Review Points

1. **No SQL injection risk:** Using parameterized queries
2. **No authorization bypass:** All conditions require explicit user match
3. **Consistent with post edit permissions:** Similar model to post editing
4. **Backwards compatible:** Existing valid operations still work
5. **Audit trail:** All changes logged to audit table

## Deployment Notes

- No database migration required
- No API contract changes
- Existing clients will see proper 403 errors instead of allowing unintended edits
- May need frontend UI updates to hide edit/delete buttons for unauthorized comments
- Admins can still edit any comment if needed for moderation

