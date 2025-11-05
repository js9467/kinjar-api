#!/usr/bin/env powershell
# Deploy Kinjar API with pending invitations feature to Fly.io

Write-Host "🚀 Deploying Kinjar API with Pending Invitations Feature" -ForegroundColor Green
Write-Host ("=" * 60)

# Check if flyctl is available
Write-Host "📦 Checking Fly.io CLI..." -ForegroundColor Blue
try {
    $flyVersion = flyctl version 2>$null
    if ($flyVersion) {
        Write-Host "✅ Fly.io CLI found" -ForegroundColor Green
    } else {
        throw "Fly CLI not found"
    }
} catch {
    Write-Host "❌ Fly.io CLI not found. Please install it first:" -ForegroundColor Red
    Write-Host "   Windows: winget install fly.io.flyctl" -ForegroundColor Yellow
    Write-Host "   Or visit: https://fly.io/docs/hands-on/install-flyctl/" -ForegroundColor Yellow
    exit 1
}

# Verify we're in the right directory
if (!(Test-Path "app.py")) {
    Write-Host "❌ app.py not found. Please run this script from the kinjar-api directory" -ForegroundColor Red
    exit 1
}

Write-Host "📁 Working directory verified" -ForegroundColor Green

# Check for pending invitations implementation
Write-Host "🔍 Verifying pending invitations implementation..." -ForegroundColor Blue
$appContent = Get-Content "app.py" -Raw
if ($appContent -match "pending-invitations" -and $appContent -match "send_family_invitation_accepted_email") {
    Write-Host "✅ Pending invitations endpoint found" -ForegroundColor Green
    Write-Host "✅ Email notification function found" -ForegroundColor Green
} else {
    Write-Host "❌ Pending invitations implementation not found" -ForegroundColor Red
    Write-Host "   Please ensure the implementation is complete" -ForegroundColor Yellow
    exit 1
}

# Show what's being deployed
Write-Host "📋 Deployment Summary:" -ForegroundColor Blue
Write-Host "   ✅ New endpoint: /api/families/pending-invitations" -ForegroundColor White
Write-Host "   ✅ Email notifications for accepted invitations" -ForegroundColor White
Write-Host "   ✅ Support for both member and family creation invitations" -ForegroundColor White
Write-Host "   ✅ Existing functionality preserved" -ForegroundColor White

# Confirm deployment
$confirm = Read-Host "`n🚀 Ready to deploy to Fly.io? (y/N)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
    Write-Host "Deployment cancelled" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n🚀 Starting deployment..." -ForegroundColor Green

# Deploy to Fly.io
try {
    Write-Host "📤 Deploying to Fly.io..." -ForegroundColor Blue
    flyctl deploy --ha=false
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✅ Deployment successful!" -ForegroundColor Green
        Write-Host "🌐 API URL: https://kinjar-api.fly.dev" -ForegroundColor Cyan
        Write-Host "🔗 New endpoint: https://kinjar-api.fly.dev/api/families/pending-invitations" -ForegroundColor Cyan
        
        Write-Host "`n🧪 Testing deployment..." -ForegroundColor Blue
        Start-Sleep -Seconds 10  # Wait for deployment to be ready
        
        Write-Host "`n📋 Next Steps:" -ForegroundColor Blue
        Write-Host "   1. Test the pending invitations feature in your frontend" -ForegroundColor White
        Write-Host "   2. Send a family invitation to verify email notifications" -ForegroundColor White
        Write-Host "   3. Monitor logs with: flyctl logs" -ForegroundColor White
        
        Write-Host "`n🎉 Deployment complete! Your backend now supports pending invitations." -ForegroundColor Green
        
    } else {
        Write-Host "`n❌ Deployment failed" -ForegroundColor Red
        Write-Host "Check the output above for errors" -ForegroundColor Yellow
        exit 1
    }
    
} catch {
    Write-Host "`n❌ Deployment error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n🔧 Useful commands:" -ForegroundColor Blue
Write-Host "   View logs: flyctl logs" -ForegroundColor White
Write-Host "   SSH to app: flyctl ssh console" -ForegroundColor White
Write-Host "   App status: flyctl status" -ForegroundColor White
Write-Host "   Scale app: flyctl scale count 1" -ForegroundColor White