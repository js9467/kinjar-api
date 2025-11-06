# Test comment permissions
$BaseUrl = "https://kinjar-api.fly.dev"
$FamilySlug = "slaughterbeck"

# Get all comments from the database to see current state
$ApiUrl = "$BaseUrl/api/admin/family/$FamilySlug/posts"
$Headers = @{
    "x-tenant-slug" = $FamilySlug
    "Content-Type" = "application/json"
}

# We need to get a token first - for testing, use direct API calls
Write-Host "Testing comment permissions..."
Write-Host "Base URL: $BaseUrl"
Write-Host "Family: $FamilySlug"

# First, let's test getting the posts and comments
Write-Host "`n=== STEP 1: Get current posts and comments ===" 
try {
    # Get all comments - try a simple query endpoint
    $Response = Invoke-WebRequest -Uri "$BaseUrl/api/comments/test" -Headers $Headers -Method GET -ErrorAction SilentlyContinue
    Write-Host $Response.Content
} catch {
    Write-Host "Error: $($_.Exception.Message)"
    # Try alternative approach
    Write-Host "Attempting alternative diagnostic approach..."
}

Write-Host "`n=== STEP 2: Check database directly ===" 
Write-Host "Need to run SQL query to see comment structure..."
Write-Host "Testing with python diagnostic script..."

