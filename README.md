# kinjar-api (Fly.io + Cloudflare R2 presign)

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit if needed
python app.py
