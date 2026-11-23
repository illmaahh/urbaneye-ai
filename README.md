# UrbanEye AI

**UrbanEye** is a shared city-operations workspace for reporting and tracking street-level infrastructure issues. It gives community members a place to submit reports and lets administrators review reports and update their status.

**Live application:** https://urbaneye-ai-0hh8.onrender.com

## Project overview

The dashboard is labelled **City Operations · Bhopal** and includes:
- Citizen account registration and sign-in.
- Report submission with issue type, location, area, severity, description and optional photo evidence.
- A shared report workspace with report status and history.
- Administrator access for reviewing reports and updating their status.
- Overview metrics, report trends and an illustrative issue-location map.

  
## GrowthX Off Campus

I'm participating in GrowthX Off Campus, sponsored by AWS.

**My Off Campus referral code: FZ4SYM**


## Technology

- **Frontend:** HTML, CSS and JavaScript in `index.html`.
- **Backend:** Python HTTP server in `server.py`.
- **Database:** Supabase PostgreSQL.
- **Evidence storage:** Private Supabase Storage bucket named `urbaneye-evidence`.
- **Hosting:** Render Web Service (Singapore region).
- **Deployment:** GitHub `main` branch with automatic deployment enabled.

## Deployment configuration

The deployed service uses these environment variables:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Supabase PostgreSQL connection string (use the Session Pooler connection for Render) |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_SECRET_KEY` | Server-side Supabase secret key |
| `SUPABASE_STORAGE_BUCKET` | Private evidence bucket; `urbaneye-evidence` |
| `URBANEYE_ADMIN_INVITE` | Private invite code required to create administrator accounts |
| `HOST` | Server bind address; `0.0.0.0` on Render |
| `COOKIE_SECURE` | Enables secure session cookies on HTTPS |
| `SESSION_HOURS` | Session lifetime in hours |

**Security:** Keep database credentials, the Supabase secret key and the administrator invite code private. Do not commit them to GitHub or include them in screenshots or presentations. The browser does not receive the Supabase secret key. Uploaded evidence is stored in a private bucket and delivered through the application after the user's access is checked.

## Database setup

The SQL schema is in `supabase/schema.sql`. Run it in the Supabase SQL Editor when creating a new project. It creates the application tables and indexes and enables row-level security. The backend connects to PostgreSQL using the server-side database connection string.

## Running and deploying

The production app is hosted at the live URL above. To deploy code changes, push commits to the `main` branch; Render is configured to deploy new commits automatically.

For a new deployment:
1. Create a Supabase project and run `supabase/schema.sql` in its SQL Editor.
2. Create a **private** Storage bucket named `urbaneye-evidence`.
3. Create a Render web service from this repository using the included `Dockerfile` / `render.yaml`.
4. Set the required environment variables in Render. Use the Supabase Session Pooler connection string for `DATABASE_URL`.
5. Keep `SUPABASE_SECRET_KEY` and `URBANEYE_ADMIN_INVITE` private.

## Current scope and limitations

- The issue map uses illustrative markers and locations; it is not connected to live GIS or GPS data.
- The image-review panel currently shows demonstration output; a trained image-classification or object-detection model is not connected.
- Email verification and password recovery are not yet configured.
- This is a student project prototype, not a live municipal dispatch system.

## Repository structure

- `index.html` — responsive frontend and client-side interactions.
- `server.py` — API, authentication, authorization, PostgreSQL access and private evidence delivery.
- `supabase/schema.sql` — database tables, indexes and row-level security setup.
- `requirements.txt` — Python dependencies.
- `Dockerfile` — container build configuration.
- `render.yaml` — Render service configuration.
