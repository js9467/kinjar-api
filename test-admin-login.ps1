# Script to help troubleshoot and upgrade admin access
$EMAIL = "slaughterbeck@gmail.com"
$PASSWORD = "WallaceLouise1!"
$USERNAME = "slaughterbeck"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Kinjar Admin Access Troubleshooting" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host ""

# Test 1: Try login with email
Write-Host "Test 1: Login with email..." -ForegroundColor Yellow
$loginBodyEmail = @{
    username = $EMAIL
    password = $PASSWORD
} | ConvertTo-Json

try {
    $response1 = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBodyEmail -ContentType "application/json"
    Write-Host "✅ SUCCESS: Email login works!" -ForegroundColor Green
    Write-Host "Token received. You have access!" -ForegroundColor Cyan
    exit 0
}
catch {
    Write-Host "❌ Email login failed" -ForegroundColor Red
}

# Test 2: Try login with username
Write-Host ""
Write-Host "Test 2: Login with username..." -ForegroundColor Yellow
$loginBodyUsername = @{
    username = $USERNAME
    password = $PASSWORD
} | ConvertTo-Json

try {
    $response2 = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBodyUsername -ContentType "application/json"
    Write-Host "✅ SUCCESS: Username login works!" -ForegroundColor Green
    Write-Host "Token received. You have access!" -ForegroundColor Cyan
    exit 0
}
catch {
    Write-Host "❌ Username login failed" -ForegroundColor Red
}

# Test 3: Try different password variations
Write-Host ""
Write-Host "Test 3: Trying admin password variations..." -ForegroundColor Yellow

$adminPasswords = @(
    "slaughterbeck123",
    "AdminPassword123", 
    "KinjarAdmin2024",
    "SecurePass456"
)

foreach ($testPassword in $adminPasswords) {
    Write-Host "  Trying password: $testPassword" -ForegroundColor Gray
    
    $testBody = @{
        username = $EMAIL
        password = $testPassword
    } | ConvertTo-Json
    
    try {
        $testResponse = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $testBody -ContentType "application/json"
        Write-Host "✅ SUCCESS: Found working password!" -ForegroundColor Green
        Write-Host "Login with:" -ForegroundColor Cyan
        Write-Host "  Email: $EMAIL" -ForegroundColor White
        Write-Host "  Password: $testPassword" -ForegroundColor White
        exit 0
    }
    catch {
        # Continue to next password
    }
}

Write-Host "❌ No working password combinations found" -ForegroundColor Red
Write-Host ""
Write-Host "SOLUTION OPTIONS:" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Option 1: Register a new admin account" -ForegroundColor Yellow
Write-Host "  Go to: https://kinjar-frontend.vercel.app/register" -ForegroundColor White
Write-Host "  Use any email/password - it may get ROOT privileges automatically" -ForegroundColor White
Write-Host ""
Write-Host "Option 2: Reset password on existing account" -ForegroundColor Yellow  
Write-Host "  The account exists but password might be different" -ForegroundColor White
Write-Host ""
Write-Host "Option 3: Use database admin script" -ForegroundColor Yellow
Write-Host "  If you have database access, run create_admin.py directly" -ForegroundColor White