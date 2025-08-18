# # kinjar-api (Fly)

A minimal Flask service for:
- Health/Version checks
- Presigned POST URLs for S3-compatible storage (Cloudflare R2)
- Strict CORS and API key auth

## Endpoints

### GET /health
Used by Fly health checks.
```bash
curl https://<your-app>.fly.dev/health