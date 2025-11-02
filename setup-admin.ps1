# PowerShell script to create ROOT admin user for Kinjar with your credentials
$ADMIN_EMAIL = "slaughterbeck@gmail.com"
$ADMIN_PASSWORD = "WallaceLouise1!"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Creating ROOT Admin User for Kinjar Platform" -ForegroundColor Green
Write-Host "Email: $ADMIN_EMAIL"
Write-Host "Password: $ADMIN_PASSWORD"
Write-Host ""

# Try to register the admin account
Write-Host "Attempting to register admin account..." -ForegroundColor Yellow

$registerBody = @{
    username = "slaughterbeck"
    email = $ADMIN_EMAIL
    password = $ADMIN_PASSWORD
    family_name = "Slaughterbeck"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$API_URL/auth/register" -Method POST -Body $registerBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "✅ SUCCESS: Admin account created successfully!" -ForegroundColor Green
    Write-Host "Login credentials:" -ForegroundColor Cyan
    Write-Host "  Email: $ADMIN_EMAIL" -ForegroundColor White
    Write-Host "  Password: $ADMIN_PASSWORD" -ForegroundColor White
    Write-Host ""
    Write-Host "Response:" -ForegroundColor Gray
    $response | ConvertTo-Json -Depth 3 | Write-Host
}
catch {
    $errorDetails = $_.Exception.Response
    if ($errorDetails) {
        $reader = New-Object System.IO.StreamReader($errorDetails.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Registration response: $responseBody" -ForegroundColor Yellow
    }
    
    $errorMessage = $_.Exception.Message
    if ($errorMessage -like "*already exists*" -or $errorMessage -like "*409*" -or $responseBody -like "*already exists*") {
        Write-Host "⚠️  Account already exists. Trying to login..." -ForegroundColor Yellow
        
        # Try to login with existing account
        $loginBody = @{
            username = $ADMIN_EMAIL
            password = $ADMIN_PASSWORD
        } | ConvertTo-Json
        
        try {
            $loginResponse = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
            Write-Host "✅ SUCCESS: Logged in successfully!" -ForegroundColor Green
            Write-Host "Your credentials work:" -ForegroundColor Cyan
            Write-Host "  Email: $ADMIN_EMAIL" -ForegroundColor White
            Write-Host "  Password: $ADMIN_PASSWORD" -ForegroundColor White
            Write-Host ""
            Write-Host "Login response:" -ForegroundColor Gray
            $loginResponse | ConvertTo-Json -Depth 3 | Write-Host
        }
        catch {
            Write-Host "❌ Login failed. Let me try username instead of email..." -ForegroundColor Red
            
            # Try with username
            $loginBodyUsername = @{
                username = "slaughterbeck"
                password = $ADMIN_PASSWORD
            } | ConvertTo-Json
            
            try {
                $loginResponse2 = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBodyUsername -ContentType "application/json"
                Write-Host "✅ SUCCESS: Logged in with username!" -ForegroundColor Green
                Write-Host "Use these credentials:" -ForegroundColor Cyan
                Write-Host "  Username: slaughterbeck" -ForegroundColor White
                Write-Host "  Password: $ADMIN_PASSWORD" -ForegroundColor White
                Write-Host ""
                Write-Host "Login response:" -ForegroundColor Gray
                $loginResponse2 | ConvertTo-Json -Depth 3 | Write-Host
            }
            catch {
                Write-Host "❌ Both email and username login failed." -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "❌ Registration failed: $errorMessage" -ForegroundColor Red
        if ($responseBody) {
            Write-Host "Server response: $responseBody" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Go to https://kinjar-frontend.vercel.app" -ForegroundColor White
Write-Host "2. Click 'Sign In' or 'Login'" -ForegroundColor White
Write-Host "3. Use your credentials:" -ForegroundColor White
Write-Host "   Email: $ADMIN_EMAIL" -ForegroundColor Gray
Write-Host "   Password: $ADMIN_PASSWORD" -ForegroundColor Gray