# Test comment permissions using PowerShell
$BaseUrl = "https://kinjar-api.fly.dev"
$FamilySlug = "slaughterbeck"

Write-Host "================================================================================
COMMENT PERMISSION TEST SCENARIOS - EXPECTED BEHAVIOR AFTER FIX
================================================================================" -ForegroundColor Cyan

$TestScenarios = @(
    @{
        Name = "Child edits own comment"
        Allow = $true
        Description = "A child should be able to edit their own comment"
    },
    @{
        Name = "Child edits another child's comment"
        Allow = $false
        Description = "A child should NOT be able to edit another child's comment"
    },
    @{
        Name = "Child edits adult's comment"
        Allow = $false
        Description = "A child should NOT be able to edit an adult's comment"
    },
    @{
        Name = "Adult edits own comment"
        Allow = $true
        Description = "An adult should be able to edit their own comment"
    },
    @{
        Name = "Adult edits another adult's comment"
        Allow = $false
        Description = "An adult should NOT be able to edit another adult's comment"
    },
    @{
        Name = "Adult edits child's comment"
        Allow = $false
        Description = "An adult should NOT be able to edit a child's own comment"
    },
    @{
        Name = "Adult edits comment posted_as their child"
        Allow = $true
        Description = "An adult should be able to edit a comment they authored and posted_as their child"
    },
    @{
        Name = "Admin edits any comment"
        Allow = $true
        Description = "An admin should be able to edit any comment in their family"
    }
)

Write-Host "`nExpected Results:`n"

foreach ($test in $TestScenarios) {
    $status = if ($test.Allow) { "✅ ALLOW" } else { "❌ DENY  " }
    Write-Host "$status | $($test.Name)"
    Write-Host "        $($test.Description)`n"
}

Write-Host "================================================================================
TESTING INSTRUCTIONS
================================================================================" -ForegroundColor Green

$Instructions = @"
To test these fixes:

1. Ensure the API has been redeployed with the permission fixes

2. Obtain authentication tokens for different roles:
   - Child token: Login as a CHILD user
   - Adult token: Login as an ADULT/MEMBER user  
   - Admin token: Login as an ADMIN/OWNER user

3. Create test comments with different authors/roles:
   - Let a child post a comment
   - Let an adult post a comment
   - Let another adult post a comment

4. Test each scenario:

   EDIT TEST (PATCH):
   `$token = "your-auth-token-here"
   `$commentId = "comment-id-to-test"
   `$headers = @{
       "Authorization" = "Bearer `$token"
       "x-tenant-slug" = "$FamilySlug"
       "Content-Type" = "application/json"
   }
   `$body = @{ content = "Updated test content" } | ConvertTo-Json
   Invoke-WebRequest -Uri "$BaseUrl/api/comments/`$commentId" -Method PATCH -Headers `$headers -Body `$body

   DELETE TEST (DELETE):
   Invoke-WebRequest -Uri "$BaseUrl/api/comments/`$commentId" -Method DELETE -Headers `$headers

5. Verify responses:
   - ✅ ALLOW cases should return HTTP 200: {"ok": true, "comment": {...}}
   - ❌ DENY cases should return HTTP 403: {"ok": false, "error": "insufficient_permissions"}

KEY FIXES APPLIED:
- Adults can ONLY edit/delete their own comments (not other adults')
- Adults can edit/delete comments they posted_as children
- Children can ONLY edit/delete their own comments
- Admins can edit/delete any comment in the family
- The API now logs the detailed reason for each permission decision
"@

Write-Host $Instructions -ForegroundColor Yellow

Write-Host "`nAPI Endpoint Reference:" -ForegroundColor Cyan
Write-Host "  Edit:   PATCH /api/comments/{comment_id}" 
Write-Host "  Delete: DELETE /api/comments/{comment_id}"
Write-Host "`nBoth require Authorization header and x-tenant-slug header"
