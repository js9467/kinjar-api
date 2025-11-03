#!/bin/bash
# Set Vercel Blob token on Fly.io
# Run this command from your kinjar-api directory:

fly secrets set BLOB_READ_WRITE_TOKEN="vercel_blob_rw_ZHcVEZkPvrrn4k2C_Pinuk0x4wXUGhwjGPq1MLuwG4DGXli"

# After setting this, the app will automatically restart and use real Vercel Blob storage
echo "✅ Vercel Blob token has been set on Fly.io"
echo "🔄 Your app will restart automatically to use the new environment variable"
echo "🎯 Now uploads will go to real Vercel Blob storage instead of mock URLs!"