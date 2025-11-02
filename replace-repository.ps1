# Kinjar Frontend Repository Replacement Script
# This script helps you replace the existing kinjar-frontend repository with the new codebase

param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath = "D:\Software\Kinjar API\kinjar-api\frontend-deploy",
    
    [Parameter(Mandatory=$false)]
    [string]$GitHubRepo = "https://github.com/js9467/kinjar-frontend.git",
    
    [Parameter(Mandatory=$false)]
    [string]$WorkingDir = ".\kinjar-frontend-new"
)

Write-Host "🚀 Kinjar Frontend Repository Replacement Script" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# Check if source directory exists
if (-not (Test-Path $SourcePath)) {
    Write-Host "❌ Source path not found: $SourcePath" -ForegroundColor Red
    exit 1
}

Write-Host "📂 Source: $SourcePath" -ForegroundColor Cyan
Write-Host "🔗 Repository: $GitHubRepo" -ForegroundColor Cyan
Write-Host "📁 Working Directory: $WorkingDir" -ForegroundColor Cyan
Write-Host ""

# Step 1: Clone the repository
Write-Host "📥 Step 1: Cloning repository..." -ForegroundColor Yellow
if (Test-Path $WorkingDir) {
    Write-Host "   Removing existing directory..." -ForegroundColor Gray
    Remove-Item -Path $WorkingDir -Recurse -Force
}

try {
    git clone $GitHubRepo $WorkingDir
    if ($LASTEXITCODE -ne 0) {
        throw "Git clone failed"
    }
    Write-Host "   ✅ Repository cloned successfully" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to clone repository: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Backup .git folder
Write-Host "💾 Step 2: Backing up .git folder..." -ForegroundColor Yellow
$gitBackupPath = "$WorkingDir\.git-backup"
try {
    Move-Item -Path "$WorkingDir\.git" -Destination $gitBackupPath
    Write-Host "   ✅ .git folder backed up" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to backup .git folder: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Clear existing files
Write-Host "🧹 Step 3: Clearing existing files..." -ForegroundColor Yellow
try {
    Get-ChildItem -Path $WorkingDir | Remove-Item -Recurse -Force
    Write-Host "   ✅ Existing files removed" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to clear files: $_" -ForegroundColor Red
    exit 1
}

# Step 4: Copy new files
Write-Host "📋 Step 4: Copying new frontend files..." -ForegroundColor Yellow
try {
    Copy-Item -Path "$SourcePath\*" -Destination $WorkingDir -Recurse
    Write-Host "   ✅ New files copied successfully" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to copy files: $_" -ForegroundColor Red
    exit 1
}

# Step 5: Restore .git folder
Write-Host "🔄 Step 5: Restoring .git folder..." -ForegroundColor Yellow
try {
    Move-Item -Path $gitBackupPath -Destination "$WorkingDir\.git"
    Write-Host "   ✅ .git folder restored" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to restore .git folder: $_" -ForegroundColor Red
    exit 1
}

# Step 6: Git operations
Write-Host "📝 Step 6: Committing changes..." -ForegroundColor Yellow
Set-Location $WorkingDir

try {
    # Add all files
    git add .
    if ($LASTEXITCODE -ne 0) {
        throw "Git add failed"
    }
    
    # Create commit
    $commitMessage = "🚀 Complete rewrite: Modern family social platform

Next.js 14 with App Router and TypeScript
Mobile-first photo/video upload with camera integration  
Family-based subdomain routing (family.kinjar.com)
Vercel Blob storage integration
JWT authentication with role management
Complete API integration with Flask backend
Progressive Web App capabilities
Responsive design for all devices

Features:
Family-based social networking with subdomains
Mobile-optimized photo/video sharing
Real-time family feeds with posts and comments
Cross-family connections and content sharing
Role-based permissions (root admin, family admin, member)
Progressive Web App with camera integration
Secure JWT authentication
Vercel Blob storage for media files

Ready for production deployment on Vercel!"

    git commit -m $commitMessage
    if ($LASTEXITCODE -ne 0) {
        throw "Git commit failed"
    }
    
    Write-Host "   ✅ Changes committed successfully" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Git operations failed: $_" -ForegroundColor Red
    Set-Location ..
    exit 1
}

# Step 7: Ask about pushing
Write-Host ""
Write-Host "🎯 Step 7: Ready to push to GitHub!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Repository is ready with the complete family social platform." -ForegroundColor White
Write-Host "This includes:" -ForegroundColor White
Write-Host "  ✅ Next.js 14 with TypeScript" -ForegroundColor Green
Write-Host "  ✅ Mobile-first design with camera integration" -ForegroundColor Green
Write-Host "  ✅ Family subdomain routing" -ForegroundColor Green
Write-Host "  ✅ Vercel Blob storage integration" -ForegroundColor Green
Write-Host "  ✅ Complete API client for your Flask backend" -ForegroundColor Green
Write-Host "  ✅ Authentication and role management" -ForegroundColor Green
Write-Host "  ✅ PWA capabilities" -ForegroundColor Green
Write-Host ""

$pushChoice = Read-Host "Do you want to push to GitHub now? (y/N)"
if ($pushChoice -eq 'y' -or $pushChoice -eq 'Y') {
    Write-Host "📤 Pushing to GitHub..." -ForegroundColor Yellow
    try {
        git push origin main
        if ($LASTEXITCODE -ne 0) {
            throw "Git push failed"
        }
        Write-Host "   ✅ Successfully pushed to GitHub!" -ForegroundColor Green
        Write-Host ""
        Write-Host "🎉 SUCCESS! Your repository has been updated!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "1. Go to Vercel Dashboard and import your GitHub repository" -ForegroundColor White
        Write-Host "2. Configure environment variables (see DEPLOYMENT.md)" -ForegroundColor White
        Write-Host "3. Set up Vercel Blob storage" -ForegroundColor White
        Write-Host "4. Configure custom domain (kinjar.com)" -ForegroundColor White
        Write-Host "5. Test the deployment!" -ForegroundColor White
        Write-Host ""
        Write-Host "📖 See DEPLOYMENT.md for detailed instructions" -ForegroundColor Cyan
    } catch {
        Write-Host "   ❌ Failed to push to GitHub: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "You can push manually later with:" -ForegroundColor Yellow
        Write-Host "   git push origin main" -ForegroundColor Gray
    }
} else {
    Write-Host ""
    Write-Host "✅ Repository prepared successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To push to GitHub later, run:" -ForegroundColor Yellow
    Write-Host "   cd $WorkingDir" -ForegroundColor Gray
    Write-Host "   git push origin main" -ForegroundColor Gray
    Write-Host ""
    Write-Host "📖 See DEPLOYMENT.md for detailed deployment instructions" -ForegroundColor Cyan
}

# Return to original directory
Set-Location ..

Write-Host ""
Write-Host "🏁 Script completed successfully!" -ForegroundColor Green
Write-Host "Working directory: $WorkingDir" -ForegroundColor Cyan