# Simple script to create ROOT admin user
$ADMIN_EMAIL = "root@kinjar.local"
$ADMIN_PASSWORD = "RootAdmin123!"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Creating ROOT Admin Account" -ForegroundColor Green
Write-Host "Email: $ADMIN_EMAIL" -ForegroundColor Cyan
Write-Host "Password: $ADMIN_PASSWORD" -ForegroundColor Cyan
Write-Host ""

$registerBody = @{
    username = "rootadmin"
    email = $ADMIN_EMAIL
    password = $ADMIN_PASSWORD
    family_name = "KinjarRoot"
} | ConvertTo-Json

try {
    Write-Host "Attempting registration..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri "$API_URL/auth/register" -Method POST -Body $registerBody -ContentType "application/json"
    Write-Host "✅ SUCCESS: ROOT admin account created!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔑 Login Credentials:" -ForegroundColor White
    Write-Host "   Email: $ADMIN_EMAIL"
    Write-Host "   Password: $ADMIN_PASSWORD"
    Write-Host ""
    Write-Host "🌐 Login at: https://kinjar-frontend.vercel.app/auth/login"
    Write-Host ""
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    Write-Host "Registration failed with status: $statusCode" -ForegroundColor Red
    
    if ($statusCode -eq 409) {
        Write-Host "Account already exists. Trying login..." -ForegroundColor Yellow
        
        $loginBody = @{
            username = $ADMIN_EMAIL
            password = $ADMIN_PASSWORD
        } | ConvertTo-Json
        
        try {
            $loginResponse = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
            Write-Host "✅ Login successful!" -ForegroundColor Green
            Write-Host "🔑 Use these credentials:" -ForegroundColor White
            Write-Host "   Email: $ADMIN_EMAIL"
            Write-Host "   Password: $ADMIN_PASSWORD"
        }
        catch {
            Write-Host "❌ Login also failed" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}