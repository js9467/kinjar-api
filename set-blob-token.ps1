# PowerShell version - Set Vercel Blob token on Fly.io
# Run this command from your kinjar-api directory:

# If you have Fly CLI installed:
# fly secrets set BLOB_READ_WRITE_TOKEN="vercel_blob_rw_ZHcVEZkPvrrn4k2C_Pinuk0x4wXUGhwjGPq1MLuwG4DGXli"

# Alternative: Install Fly CLI first, then set the secret
Write-Host "To configure Vercel Blob storage:"
Write-Host ""
Write-Host "1. Install Fly CLI (if not already installed):"
Write-Host "   iwr https://fly.io/install.ps1 -useb | iex"
Write-Host ""
Write-Host "2. Set the Vercel Blob token:"
Write-Host "   fly secrets set BLOB_READ_WRITE_TOKEN=vercel_blob_rw_ZHcVEZkPvrrn4k2C_Pinuk0x4wXUGhwjGPq1MLuwG4DGXli"
Write-Host ""
Write-Host "3. Verify it is set:"
Write-Host "   fly secrets list"
Write-Host ""
Write-Host "After this, uploads will use real Vercel Blob storage!"