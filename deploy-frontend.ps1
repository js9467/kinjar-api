#!/usr/bin/env pwsh

# Kinjar Frontend Repository Replacement Script - Simple Version
Write-Host "🚀 Kinjar Frontend Repository Replacement" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

$REPO_URL = "https://github.com/js9467/kinjar-frontend.git"
$SOURCE_DIR = "D:\Software\Kinjar API\kinjar-api\frontend-deploy"
$WORK_DIR = "D:\Software\Kinjar API\kinjar-frontend-replacement"

# Step 1: Verify source directory
Write-Host "`n📁 Step 1: Verifying source directory..." -ForegroundColor Yellow
if (-not (Test-Path $SOURCE_DIR)) {
    Write-Host "❌ Source directory not found: $SOURCE_DIR" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Source directory found" -ForegroundColor Green

# Step 2: Clean up and clone repository
Write-Host "`n🔄 Step 2: Preparing workspace..." -ForegroundColor Yellow
if (Test-Path $WORK_DIR) {
    Remove-Item -Path $WORK_DIR -Recurse -Force
}

Write-Host "Cloning repository..." -ForegroundColor Gray
git clone $REPO_URL $WORK_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to clone repository" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Repository cloned successfully" -ForegroundColor Green

# Step 3: Navigate to work directory
Set-Location $WORK_DIR

# Step 4: Remove existing files (keep .git)
Write-Host "`n🗑️  Step 3: Removing existing files..." -ForegroundColor Yellow
Get-ChildItem -Path . -Exclude .git | Remove-Item -Recurse -Force
Write-Host "✅ Existing files removed" -ForegroundColor Green

# Step 5: Copy new files
Write-Host "`n📋 Step 4: Copying new platform files..." -ForegroundColor Yellow
Copy-Item -Path "$SOURCE_DIR\*" -Destination . -Recurse -Force
Write-Host "✅ New platform files copied" -ForegroundColor Green

# Step 6: Git operations
Write-Host "`n📝 Step 5: Preparing git commit..." -ForegroundColor Yellow

# Configure git
git config user.name "Kinjar Platform Deploy"
git config user.email "deploy@kinjar.com"

# Add all files
git add .

# Create commit
$commitMessage = "🚀 Complete rewrite: Modern family social platform

Features:
- Next.js 14 with App Router and TypeScript
- Mobile-first photo/video upload with camera integration  
- Family-based subdomain routing (family.kinjar.com)
- Vercel Blob storage integration (150MB files)
- JWT authentication with role management
- Complete API integration with Flask backend
- Progressive Web App capabilities
- Responsive design for all devices

Ready for production deployment on Vercel!"

git commit -m $commitMessage
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Git commit failed" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Changes committed successfully" -ForegroundColor Green

# Step 7: Ask about pushing
Write-Host "`n🚀 Step 6: Ready to push to GitHub!" -ForegroundColor Yellow
$pushChoice = Read-Host "Push changes to GitHub now? (Y/n)"

if ($pushChoice -ne "n" -and $pushChoice -ne "N") {
    Write-Host "Pushing to GitHub..." -ForegroundColor Gray
    git push origin main
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
    } else {
        Write-Host "❌ Push failed. You can push manually later with:" -ForegroundColor Yellow
        Write-Host "   cd `"$WORK_DIR`"" -ForegroundColor Gray
        Write-Host "   git push origin main" -ForegroundColor Gray
    }
} else {
    Write-Host "⏸️  Skipping push. To push later, run:" -ForegroundColor Yellow
    Write-Host "   cd `"$WORK_DIR`"" -ForegroundColor Gray
    Write-Host "   git push origin main" -ForegroundColor Gray
}

# Step 8: Show completion message
Write-Host "`n🎉 Repository Replacement Complete!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
Write-Host "1. 🌐 Go to Vercel Dashboard: https://vercel.com/dashboard" -ForegroundColor White
Write-Host "2. 📦 Import your updated kinjar-frontend repository" -ForegroundColor White
Write-Host "3. ⚙️  Configure environment variables:" -ForegroundColor White
Write-Host "   - KINJAR_API_URL=https://kinjar-api.fly.dev" -ForegroundColor Gray
Write-Host "   - BLOB_READ_WRITE_TOKEN=your-vercel-blob-token" -ForegroundColor Gray
Write-Host "   - NEXTAUTH_SECRET=your-secure-secret" -ForegroundColor Gray
Write-Host "4. 🗄️  Create Vercel Blob storage" -ForegroundColor White
Write-Host "5. 🌍 Configure domains: kinjar.com and *.kinjar.com" -ForegroundColor White

Write-Host "`n🔗 Important Links:" -ForegroundColor Cyan
Write-Host "- Repository: https://github.com/js9467/kinjar-frontend" -ForegroundColor White
Write-Host "- Vercel: https://vercel.com/dashboard" -ForegroundColor White
Write-Host "- Backend: https://kinjar-api.fly.dev" -ForegroundColor White

Write-Host "`n📖 For detailed instructions, see: $WORK_DIR\DEPLOYMENT.md" -ForegroundColor Cyan

# Cleanup
Write-Host "`n🧹 Cleanup:" -ForegroundColor Cyan
$cleanupChoice = Read-Host "Remove work directory? (Y/n)"
if ($cleanupChoice -ne "n" -and $cleanupChoice -ne "N") {
    Set-Location "D:\Software\Kinjar API\kinjar-api"
    Remove-Item -Path $WORK_DIR -Recurse -Force
    Write-Host "✅ Work directory cleaned up" -ForegroundColor Green
} else {
    Set-Location "D:\Software\Kinjar API\kinjar-api"
    Write-Host "📁 Files kept at: $WORK_DIR" -ForegroundColor Yellow
}

Write-Host "`n🚀 Your family social platform is ready for deployment!" -ForegroundColor Green