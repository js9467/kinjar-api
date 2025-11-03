# Troubleshooting Vercel Blob Token on Fly.io

## Current Status
The API shows the blob token is NOT configured:
- blob_token_configured: false
- blob_token_length: 0

## Steps to Fix:

### 1. Install Fly CLI (if not installed)
```powershell
iwr https://fly.io/install.ps1 -useb | iex
```

### 2. Check current secrets
```powershell
fly secrets list
```

### 3. Set the correct secret
```powershell
fly secrets set BLOB_READ_WRITE_TOKEN="vercel_blob_rw_ZHcVEZkPvrrn4k2C_Pinuk0x4wXUGhwjGPq1MLuwG4DGXli"
```

### 4. Verify it's set
```powershell
fly secrets list
```
You should see "BLOB_READ_WRITE_TOKEN" in the list.

### 5. Restart the app (if needed)
```powershell
fly deploy --no-build
```

### 6. Test the configuration
```powershell
curl https://kinjar-api.fly.dev/debug/env
```
Should show: "blob_token_configured": true

### 7. Test upload
```powershell
python test-api-blob-config.py
```
Should return a real Vercel Blob URL starting with "https://...vercel-storage.com/"

## Expected Result
Once fixed, uploads will return real Vercel Blob URLs instead of mock URLs!