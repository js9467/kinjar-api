# Create fresh admin account for ROOT access
$ADMIN_EMAIL = "admin.slaughterbeck@gmail.com"  # Slightly different email
$ADMIN_PASSWORD = "WallaceLouise1!"
$API_URL = "https://kinjar-api.fly.dev"

Write-Host "Creating Fresh Admin Account" -ForegroundColor Green
Write-Host "Email: $ADMIN_EMAIL"
Write-Host "Password: $ADMIN_PASSWORD"
Write-Host ""

$registerBody = @{
    username = "adminslaughterbeck"
    email = $ADMIN_EMAIL
    password = $ADMIN_PASSWORD
    family_name = "SlaughterbeckAdmin"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$API_URL/auth/register" -Method POST -Body $registerBody -ContentType "application/json"
    Write-Host "✅ SUCCESS: Fresh admin account created!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔑 Your ROOT Admin Credentials:" -ForegroundColor Cyan
    Write-Host "   Email: $ADMIN_EMAIL" -ForegroundColor White
    Write-Host "   Password: $ADMIN_PASSWORD" -ForegroundColor White
    Write-Host ""
    Write-Host "🌐 Login at: https://kinjar-frontend.vercel.app" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Response details:" -ForegroundColor Gray
    $response | ConvertTo-Json -Depth 3
}
catch {
    Write-Host "Registration failed, but let's try the original account registration:" -ForegroundColor Yellow
    Write-Host ""
    
    # Try with original email in case it works now
    $originalBody = @{
        username = "slaughterbeck"
        email = "slaughterbeck@gmail.com"
        password = "WallaceLouise1!"
        family_name = "Slaughterbeck"
    } | ConvertTo-Json
    
    try {
        $response2 = Invoke-RestMethod -Uri "$API_URL/auth/register" -Method POST -Body $originalBody -ContentType "application/json"
        Write-Host "✅ SUCCESS: Original account registration worked!" -ForegroundColor Green
        Write-Host ""
        Write-Host "🔑 Your ROOT Admin Credentials:" -ForegroundColor Cyan
        Write-Host "   Email: slaughterbeck@gmail.com" -ForegroundColor White
        Write-Host "   Password: WallaceLouise1!" -ForegroundColor White
        Write-Host ""
        Write-Host "🌐 Login at: https://kinjar-frontend.vercel.app" -ForegroundColor Yellow
    }
    catch {
        Write-Host "❌ Both registration attempts failed." -ForegroundColor Red
        Write-Host ""
        Write-Host "🎯 MANUAL OPTION:" -ForegroundColor Cyan
        Write-Host "1. Go to: https://kinjar-frontend.vercel.app/register" -ForegroundColor White
        Write-Host "2. Register with:" -ForegroundColor White
        Write-Host "   Email: slaughterbeck@gmail.com" -ForegroundColor Gray
        Write-Host "   Password: WallaceLouise1!" -ForegroundColor Gray
        Write-Host "   Username: slaughterbeck" -ForegroundColor Gray
        Write-Host "   Family: Slaughterbeck" -ForegroundColor Gray
        Write-Host ""
        Write-Host "The system may automatically grant you ROOT admin privileges!" -ForegroundColor Yellow
    }
}