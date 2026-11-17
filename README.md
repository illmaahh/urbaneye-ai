# UrbanEye AI

UrbanEye is a shared infrastructure reporting application. Accounts, sessions, reports, status changes and uploaded evidence are stored by the server in SQLite. Passwords are PBKDF2 hashed; login sessions use random, server-side tokens in `HttpOnly`, `SameSite=Strict` cookies. The browser no longer stores accounts or reports in local storage.

## Run on this computer

1. Open PowerShell in this folder and run `.\start.ps1`.
2. On first run, copy the administrator invite code printed in the terminal.
3. Open `http://localhost:8000`, choose **Create an account**, enter your name and email, and use that invite code for the administrator account.
4. Share the local address with other people on this computer. Their accounts and reports are stored in the same database.

The local server is bound to this computer only. Other teachers cannot reach it over the internet until it is deployed to a public server.

## Publish for teachers and other users

The included Docker Compose setup serves the app over HTTPS using Caddy and keeps the database and uploaded photos in persistent Docker volumes.

1. Provision a Linux server with Docker and Docker Compose, and point your domain's DNS records to that server.
2. Copy `.env.example` to `.env`. Set `DOMAIN` and `PUBLIC_ORIGIN` to your real domain. Replace `URBANEYE_ADMIN_INVITE` with a long random secret.
3. Open inbound ports 80 and 443 on the server, then run `docker compose up -d --build`.
4. Open your HTTPS domain, create the administrator account with the invite, then share the public URL with teachers and users. People without the invite can create citizen accounts and submit reports.

Keep `.env` private. Back up the `urbaneye_data` Docker volume regularly. Anyone holding the administrator invite can create an administrator account; rotate the invite after setting up the initial admins.

## What is real and what is still a project extension

- Real now: shared account registration and sign-in, server-side sessions, sign-out, role-based report visibility, report creation, optional photo storage, administrator status changes, and persistent shared SQLite data.
- Administrator accounts require the private invite code. Ordinary registrations receive citizen access.
- Still to connect: email verification and password recovery, a trained YOLO inference service, live geocoding and map tiles, and a production email provider. The map illustration is labelled and does not imply real GPS positions.
- The SQLite setup fits a small project deployment. A larger public service should move to a managed PostgreSQL database and add monitoring, backups and an email verification provider.

## Main files

- `index.html` — responsive web interface.
- `server.py` — application API, authentication, permissions, database and private image delivery.
- `compose.yaml`, `Dockerfile`, `Caddyfile` — HTTPS deployment setup.
- `start.ps1` — local Windows launcher; creates a private local admin invite on first run.
