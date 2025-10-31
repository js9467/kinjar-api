# kinjar-api (Fly.io + Cloudflare R2 presign)

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit if needed
python app.py
```

## Configuration

The API expects the following environment variables:

| Name | Required | Description |
| ---- | -------- | ----------- |
| `S3_BUCKET` | ✅ | Cloudflare R2 bucket used for media uploads. |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | ✅ | Credentials for presigning upload/download URLs. |
| `DATABASE_URL` | ✅ | Neon Postgres connection string. |
| `JWT_SECRET` | ✅ | Secret for signing session cookies. |
| `ROOT_DOMAIN` | ➖ | Base domain used to build tenant subdomains (defaults to `kinjar.com`). |
| `API_KEYS` | ➖ | Optional comma separated list of API keys used to guard media routes. |
| `ALLOWED_ORIGINS` | ➖ | Optional comma separated list of origins to allow for CORS. |
| `ROOT_EMAILS` | ➖ | Comma separated list of emails that should automatically receive the `ROOT` role on first registration. |

## Multi-family administration

The backend now understands **tenants** (family spaces) and **global settings**. All tenant and settings APIs require a session cookie for a `ROOT` user (Kinjar admin).

### Tenants & subdomains

| Route | Method | Purpose |
| ----- | ------ | ------- |
| `/admin/tenants` | `GET` | List all tenants with their assigned slug, domain, and members. |
| `/admin/tenants` | `POST` | Create a tenant. Provide `name`, optional `slug`, and optional `ownerEmail`. |
| `/admin/tenants/<tenantId>` | `PATCH` | Update a tenant `name` and/or `slug`. |
| `/admin/tenants/<tenantId>/members` | `POST` | Add or update a member for a tenant. Body: `email` and optional `role` (`OWNER`, `ADMIN`, `MEMBER`). |
| `/admin/tenants/<tenantId>/members` | `DELETE` | Remove a member from a tenant by `email`. |

To stand up the first family space (`slaughterbeck.kinjar.com`), authenticate as an admin and run:

```bash
curl -X POST https://api.kinjar.com/admin/tenants \
  -H "Content-Type: application/json" \
  -H "Cookie: kinjar_session=<ROOT session token>" \
  -d '{"name": "Slaughterbeck Family", "slug": "slaughterbeck"}'
```

The response includes the generated tenant ID and the full subdomain (computed from `ROOT_DOMAIN`). Use the `members` endpoints to invite additional family members.

### Global settings

| Route | Method | Purpose |
| ----- | ------ | ------- |
| `/admin/settings` | `GET` | Retrieve all global settings as key/value pairs. |
| `/admin/settings/<key>` | `PUT` | Upsert a JSON value for a given key. Body: `{ "value": ... }`. |
| `/admin/settings/<key>` | `DELETE` | Remove a key from the global settings store. |

Global settings are stored as JSON and can be used to control Kinjar-wide flags (e.g., toggles for new upload flows) that the frontend can read.
