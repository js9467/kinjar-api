# Post Permissions Debugging Guide

## Current Issues

### Frontend Issues
1. Child shows edit/delete buttons on other children's posts
2. Adult cannot edit child's posts (getting 403)
3. Frontend says `canEdit=false, canDelete=false` but buttons still show

### Backend Issues  
1. Admin/Adult trying to edit child post gets 403 forbidden
2. Backend is blocking legitimate parent->child edits

## Root Cause Analysis

From the logs:
```
Post by LeAnne Mohler: authorRole=undefined, postedAsRole=undefined
Post authorId: 0c80b350-dc03-4ec6-abba-da79e8212973
User id: b88af6a7-bfe4-4638-94c3-9476aa9d1bcf
```

**Problem**: The post's `authorId` doesn't match any member in `family.members`. This could mean:
1. LeAnne Mohler is a child profile, but the lookup is failing
2. The `authorId` in the post doesn't match the child's `userId`
3. The post might have a `posted_as_id` that isn't being returned by the backend

## Backend Check Steps

1. Check if backend is returning `posted_as_id` in post responses
2. Verify child user IDs match between posts and family members
3. Check backend permission logic for parent editing child posts

## Frontend Check Steps

1. Verify `postedAsId` is being extracted from API responses
2. Check if child profiles have correct `userId` mapping
3. Ensure permission logic properly handles unknown roles

## Testing Commands

### Check post data structure:
```sql
SELECT id, author_id, posted_as_id, content, created_at 
FROM content_posts 
WHERE id = 'f1242932-09cb-4523-ac89-6ad730ba68e1';
```

### Check user/child relationship:
```sql
SELECT u.id, u.display_name, u.email, tu.role, tu.tenant_id
FROM users u
JOIN tenant_users tu ON u.id = tu.user_id
WHERE u.display_name LIKE '%LeAnne%' OR u.display_name LIKE '%Mohler%';
```

### Check family members:
```sql
SELECT u.id, u.display_name, tu.role
FROM tenant_users tu
JOIN users u ON tu.user_id = u.id
WHERE tu.tenant_id = (SELECT id FROM tenants WHERE slug = 'slaughterbeck');
```
