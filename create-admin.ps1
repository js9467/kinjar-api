# PowerShell script to create ROOT admin user for Kinjar
# This uses the create_admin.py script on your backend

$ADMIN_EMAIL = "admin@kinjar.com"
$ADMIN_PASSWORD = "slaughterbeck123"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Creating ROOT Admin User for Kinjar Platform" -ForegroundColor Green
Write-Host "Email: $ADMIN_EMAIL"
Write-Host "Password: $ADMIN_PASSWORD"
Write-Host ""

# Method 1: Try to register as admin (if ROOT_EMAILS includes this email)
Write-Host "Attempting to register admin account..." -ForegroundColor Yellow

$registerBody = @{
    username = "admin"
    email = $ADMIN_EMAIL
    password = $ADMIN_PASSWORD
    family_name = "KinjarAdmin"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$API_URL/auth/register" -Method POST -Body $registerBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "✅ SUCCESS: Admin account created successfully!" -ForegroundColor Green
    Write-Host "You can now login with:" -ForegroundColor Cyan
    Write-Host "  Email: $ADMIN_EMAIL" -ForegroundColor White
    Write-Host "  Password: $ADMIN_PASSWORD" -ForegroundColor White
    exit 0
}
catch {
    $errorMessage = $_.Exception.Message
    if ($errorMessage -like "*already exists*" -or $errorMessage -like "*409*") {
        Write-Host "⚠️  Account already exists. Trying to login..." -ForegroundColor Yellow
        
        # Try to login
        $loginBody = @{
            username = $ADMIN_EMAIL
            password = $ADMIN_PASSWORD
        } | ConvertTo-Json
        
        try {
            $loginResponse = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
            Write-Host "✅ SUCCESS: Logged in successfully!" -ForegroundColor Green
            Write-Host "You can use these credentials:" -ForegroundColor Cyan
            Write-Host "  Email: $ADMIN_EMAIL" -ForegroundColor White
            Write-Host "  Password: $ADMIN_PASSWORD" -ForegroundColor White
        }
        catch {
            Write-Host "❌ Login failed. Account exists but password may be different." -ForegroundColor Red
            Write-Host "Try other passwords from admin_passwords.txt" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "❌ Registration failed: $errorMessage" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Alternative Admin Credentials:" -ForegroundColor Cyan
Write-Host "Try these password combinations with email: $ADMIN_EMAIL" -ForegroundColor White
Write-Host "  - AdminPassword123" -ForegroundColor Gray
Write-Host "  - KinjarAdmin2024" -ForegroundColor Gray  
Write-Host "  - slaughterbeck123" -ForegroundColor Gray
Write-Host "  - SecurePass456" -ForegroundColor Gray
Write-Host ""
Write-Host "Or register any email and it may get ROOT privileges if configured." -ForegroundColor Yellow