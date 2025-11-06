# EXACT CODE CHANGES

## File: app.py

### Change 1: PATCH /api/comments/<comment_id> - Edit Comment Permissions

**Location: Lines 5246-5290**

```diff
                # Permission logic (UPDATED: 2025-11-06):
-               # 1. Root admins and tenant ADMINs/OWNERs can edit any comment
-               # 2. Adults can edit their own comments OR child comments (posted_as_id refers to a CHILD)
-               # 3. Children can ONLY edit their own comments (not other children's)
-               # Updated: 2025-11-06 - Fixed child permission isolation
+               # 1. Root admins and tenant ADMINs/OWNERs can edit any comment
+               # 2. Adults/Members can ONLY edit their own comments OR comments posted_as their children
+               # 3. Children can ONLY edit their own comments (not other children's or adults')
                
                can_edit = False
                reason = ""
                
                if is_root_admin or current_role in ['ADMIN', 'OWNER']:
                    can_edit = True
                    reason = f"Admin/Owner {user['id']} can edit any comment"
                elif current_role in ['ADULT', 'MEMBER']:
-                   # Adults can edit their own comments
+                   # Adults can ONLY edit their own comments
                    if comment['author_id'] == user['id']:
                        can_edit = True
                        reason = f"Adult {user['id']} can edit their own comment"
-                   # Adults can edit child comments (where posted_as_id refers to a child)
-                   elif has_posted_as_id and comment.get('posted_as_id') and _is_child_role(posted_as_role):
+                   # Adults can ONLY edit comments posted_as their children (not authored by children)
+                   # This means the adult posted the comment under a child's name
+                   elif has_posted_as_id and comment.get('posted_as_id') and comment['author_id'] == user['id'] and _is_child_role(posted_as_role):
                        can_edit = True
-                       reason = (
-                           f"Adult {user['id']} can edit child comment (posted_as child role {posted_as_role})"
-                       )
-                   elif author_role and _is_child_role(author_role):
-                       can_edit = True
-                       reason = (
-                           f"Adult {user['id']} can edit child comment authored by role {author_role}"
-                       )
+                       reason = (
+                           f"Adult {user['id']} can edit comment they authored and posted_as child {comment.get('posted_as_id')}"
+                       )
+                   else:
+                       can_edit = False
+                       reason = (
+                           f"Adult {user['id']} cannot edit this comment (author: {comment['author_id']}, "
+                           f"posted_as: {comment.get('posted_as_id', 'None')}, author_role: {author_role})"
+                       )
                elif current_role and _is_child_role(current_role):
                    # Children can only edit their own comments
                    if comment['author_id'] == user['id']:
                        can_edit = True
                        reason = f"Child {user['id']} can edit their own comment"
-                   # Children CANNOT edit other children's comments
                    else:
-                       can_edit = False
-                       reason = f"Child {user['id']} cannot edit other users' comments (author: {comment['author_id']}, posted_as: {comment.get('posted_as_id', 'None')})"
+                       # Children CANNOT edit anyone else's comments
+                       can_edit = False
+                       reason = (
+                           f"Child {user['id']} cannot edit other users' comments (author: {comment['author_id']}, "
+                           f"posted_as: {comment.get('posted_as_id', 'None')})"
+                       )
```

**Key Change:** Added `comment['author_id'] == user['id']` check to the posted_as condition:
```python
# BEFORE (WRONG):
elif has_posted_as_id and comment.get('posted_as_id') and _is_child_role(posted_as_role):
    can_edit = True  # BUG: Any adult can edit!

# AFTER (FIXED):
elif has_posted_as_id and comment.get('posted_as_id') and comment['author_id'] == user['id'] and _is_child_role(posted_as_role):
    can_edit = True  # SAFE: Only the adult who authored it
```

---

### Change 2: DELETE /api/comments/<comment_id> - Delete Comment Permissions

**Location: Lines 5405-5439**

**Identical fix applied** to the delete_comment_by_uuid function:

```diff
                # Permission logic (UPDATED: 2025-11-06):
-               # 1. Root admins and tenant ADMINs/OWNERs can delete any comment
-               # 2. Adults can delete their own comments OR child comments (posted_as_id refers to a CHILD)
-               # 3. Children can ONLY delete their own comments (not other children's)
+               # 1. Root admins and tenant ADMINs/OWNERs can delete any comment
+               # 2. Adults/Members can ONLY delete their own comments OR comments posted_as their children
+               # 3. Children can ONLY delete their own comments (not other children's or adults')
                
                can_delete = False
                reason = ""
                
                if is_root_admin or current_role in ['ADMIN', 'OWNER']:
                    can_delete = True
                    reason = f"Admin/Owner {user['id']} can delete any comment"
                elif current_role in ['ADULT', 'MEMBER']:
-                   # Adults can delete their own comments
+                   # Adults can ONLY delete their own comments
                    if comment['author_id'] == user['id']:
                        can_delete = True
                        reason = f"Adult {user['id']} can delete their own comment"
-                   # Adults can delete child comments (where posted_as_id refers to a child)
-                   elif has_posted_as_id and comment.get('posted_as_id') and _is_child_role(posted_as_role):
+                   # Adults can ONLY delete comments posted_as their children (not authored by children)
+                   # This means the adult posted the comment under a child's name
+                   elif has_posted_as_id and comment.get('posted_as_id') and comment['author_id'] == user['id'] and _is_child_role(posted_as_role):
                        can_delete = True
-                       reason = (
-                           f"Adult {user['id']} can delete child comment (posted_as child role {posted_as_role})"
-                       )
-                   elif author_role and _is_child_role(author_role):
-                       can_delete = True
-                       reason = (
-                           f"Adult {user['id']} can delete child comment authored by role {author_role}"
-                       )
+                       reason = (
+                           f"Adult {user['id']} can delete comment they authored and posted_as child {comment.get('posted_as_id')}"
+                       )
+                   else:
+                       can_delete = False
+                       reason = (
+                           f"Adult {user['id']} cannot delete this comment (author: {comment['author_id']}, "
+                           f"posted_as: {comment.get('posted_as_id', 'None')}, author_role: {author_role})"
+                       )
                elif current_role and _is_child_role(current_role):
                    # Children can only delete their own comments
                    if comment['author_id'] == user['id']:
                        can_delete = True
                        reason = f"Child {user['id']} can delete their own comment"
                    else:
-                       # Children CANNOT delete other users' comments
+                       # Children CANNOT delete anyone else's comments
                        can_delete = False
                        reason = (
-                           f"Child {user['id']} cannot delete other users' comments "
-                           f"(author: {comment['author_id']}, posted_as: {comment.get('posted_as_id', 'None')})"
+                           f"Child {user['id']} cannot delete other users' comments (author: {comment['author_id']}, "
+                           f"posted_as: {comment.get('posted_as_id', 'None')})"
                        )
```

---

## Summary of Changes

**Total Lines Modified:** ~44 lines across 2 functions

**Critical Fix:** Added `comment['author_id'] == user['id']` check to both the edit and delete permission logic for adults editing/deleting "posted_as child" comments.

**Result:** 
- ❌ Removed: Ability for adults to edit other adults' comments
- ❌ Removed: Ability for adults to edit children's own comments  
- ❌ Removed: Ability for children to edit other children's comments
- ✅ Preserved: Admins can still edit any comment
- ✅ Preserved: Adults can edit comments they posted_as their children
- ✅ Preserved: Users can edit their own comments
