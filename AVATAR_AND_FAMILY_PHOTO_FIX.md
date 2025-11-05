# Avatar and Family Photo Fix Summary

## Changes Made

### Backend API Updates (app.py)

#### 1. Added Family Photo Upload Endpoint
- **Endpoint**: `POST /api/families/<family_id>/upload-photo`
- **Purpose**: Upload a family avatar/photo
- **Access**: Requires OWNER or ADMIN role
- **Returns**: `familyPhotoUrl` after successful upload
- **Storage**: Uses Vercel Blob storage

#### 2. Fixed `/api/posts` Response Format
- **Issue**: Posts were returning snake_case database fields without proper avatar formatting
- **Fix**: Added response formatter that:
  - Converts all fields to camelCase
  - Properly maps `author_avatar` → `authorAvatarUrl`
  - Properly maps `author_avatar_color` → `authorAvatarColor`  
  - Supports both direct author and "posted as" child avatars
  - Includes family metadata for cross-family posts

#### 3. Fixed `/api/posts/<post_id>/comments` Response Format  
- **Issue**: Comments returned snake_case without proper avatar fields
- **Fix**: Added response formatter that:
  - Converts all fields to camelCase
  - Maps `author_avatar` → `authorAvatarUrl`
  - Maps `author_avatar_color` → `authorAvatarColor`
  - Ensures proper date formatting

#### 4. Existing Family Details Update Endpoint
- **Endpoint**: `PATCH /api/families/<family_id>` (already existed)
- **Supports**: Updating family name, slug, and description
- **Access**: Requires OWNER or ADMIN role

### Database Schema
All necessary tables already exist:
- `user_profiles.avatar_url` - stores user avatar URLs
- `user_profiles.avatar_color` - stores user avatar colors
- `family_settings.family_photo` - stores family photo URL

### SQL Queries Already Updated
The following queries already JOIN with `user_profiles` and fetch avatar data:
- `get_tenant_posts()` - fetches `author_avatar`, `author_avatar_color`
- `get_cross_family_posts()` - fetches `author_avatar`, `author_avatar_color`
- `get_post_comments()` - fetches `author_avatar`, `author_avatar_color`
- `get_family_by_slug()` - fetches member `avatar_url`

## Frontend Changes Needed

### 1. Update API Client (src/lib/api.ts)
The frontend API client already transforms responses correctly:
- `getFamilyPosts()` - maps to `authorAvatarUrl`
- `getConnectedFamiliesFeed()` - maps to `authorAvatarUrl`  
- `getPublicFeed()` - maps to `authorAvatarUrl`
- `getPostComments()` - maps to `authorAvatarUrl`

### 2. Add Family Settings UI (Needed)
Create or update family admin component to include:
- Form to edit family name
- Form to edit family slug
- Form to edit family description
- File upload for family photo
- Preview of current family photo

**Component Location**: `src/components/family/EnhancedFamilyAdmin.tsx` or create new settings tab

**API Calls Needed**:
```typescript
// Update family details
await api.updateFamily(familyId, {
  name: newName,
  slug: newSlug,
  description: newDescription
});

// Upload family photo
const formData = new FormData();
formData.append('file', photoFile);
const response = await fetch(`${API_URL}/api/families/${familyId}/upload-photo`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData
});
```

### 3. Display Family Photos
Update family headers to show `familyPhoto` where available:
- Family dashboard header
- Family directory cards
- Connected families list

## Testing Checklist

### Backend
- [x] Family photo upload endpoint created
- [x] Posts endpoint returns proper camelCase with avatars
- [x] Comments endpoint returns proper camelCase with avatars  
- [ ] Test family photo upload via API
- [ ] Test family details update via API
- [ ] Verify avatar URLs appear in post responses
- [ ] Verify avatar URLs appear in comment responses

### Frontend
- [x] PublicFeed.tsx component rebuilt cleanly
- [x] Avatar component created for consistent display
- [ ] Add family settings form UI
- [ ] Add family photo upload UI
- [ ] Test family name/slug/description editing
- [ ] Test family photo upload
- [ ] Verify avatars display in posts
- [ ] Verify avatars display in comments
- [ ] Verify family photos display in headers

## Root Cause Analysis

### Why Avatars Weren't Showing:
1. ✅ Backend SQL queries were correct (fetching from user_profiles)
2. ✅ Database has the data (avatar_url column exists)
3. ❌ **API responses were using snake_case** (author_avatar instead of authorAvatarUrl)
4. ❌ Frontend was receiving `author_avatar` but expecting `authorAvatarUrl`

### The Fix:
- Added response formatters to `/api/posts` and `/api/posts/<post_id>/comments`
- These formatters convert snake_case → camelCase
- Properly map database fields to frontend-expected names
- Maintain compatibility with existing frontend code

## Next Steps

1. **Deploy Backend** - Deploy updated app.py to Fly.io
2. **Test Avatars** - Verify avatars now appear in posts and comments
3. **Add Family Settings UI** - Create the frontend form for editing family details
4. **Add Family Photo Upload** - Create UI for uploading family photos
5. **Test Family Editing** - Verify all family update operations work
