# Test the ROOT admin login and check user details
$ADMIN_EMAIL = "root@kinjar.local"
$ADMIN_PASSWORD = "RootAdmin123!"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Testing ROOT Admin Login" -ForegroundColor Green
Write-Host ""

$loginBody = @{
    username = $ADMIN_EMAIL
    password = $ADMIN_PASSWORD
} | ConvertTo-Json

try {
    Write-Host "Attempting login..." -ForegroundColor Yellow
    $loginResponse = Invoke-RestMethod -Uri "$API_URL/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    
    Write-Host "✅ Login successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Login Response:" -ForegroundColor Cyan
    $loginResponse | ConvertTo-Json -Depth 3
    Write-Host ""
    
    # Now test getting current user info with the token
    $token = $loginResponse.access_token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    Write-Host "Getting user details..." -ForegroundColor Yellow
    $userResponse = Invoke-RestMethod -Uri "$API_URL/auth/me" -Method GET -Headers $headers
    
    Write-Host "✅ User details retrieved!" -ForegroundColor Green
    Write-Host ""
    Write-Host "User Details:" -ForegroundColor Cyan
    $userResponse | ConvertTo-Json -Depth 3
    
    Write-Host ""
    Write-Host "🔍 Analysis:" -ForegroundColor White
    Write-Host "User ID: $($userResponse.id)" -ForegroundColor Gray
    Write-Host "Email: $($userResponse.email)" -ForegroundColor Gray
    Write-Host "Global Role: $($userResponse.global_role)" -ForegroundColor Yellow
    Write-Host "Username: $($userResponse.username)" -ForegroundColor Gray
    
    if ($userResponse.global_role -eq "ROOT") {
        Write-Host "✅ ROOT privileges confirmed!" -ForegroundColor Green
    } else {
        Write-Host "❌ ROOT privileges NOT found. Current role: $($userResponse.global_role)" -ForegroundColor Red
    }
}
catch {
    Write-Host "❌ Error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}