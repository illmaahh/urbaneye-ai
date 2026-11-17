#!/usr/bin/env python3
"""UrbanEye AI application server backed by Supabase Postgres and private Storage."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parent
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "24"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") not in ("0", "false", "False")
ADMIN_INVITE = os.environ.get("URBANEYE_ADMIN_INVITE", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")
STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "urbaneye-evidence")
MAX_BODY = 9 * 1024 * 1024
MAX_IMAGE = 6 * 1024 * 1024
ITERATIONS = 310_000
STATUSES = {"Pending", "Verified", "Assigned", "In Progress", "Resolved", "Rejected"}
LOGIN_LIMIT: dict[str, list[float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured.")
    return psycopg.connect(DATABASE_URL, sslmode=os.environ.get("DB_SSLMODE", "require"), row_factory=dict_row)


def initialize() -> None:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SECRET_KEY must be configured.")
    with connect() as db:
        db.execute("DELETE FROM public.sessions WHERE expires_at < %s", (int(time.time()),))


def storage_request(method: str, key: str, data: bytes | None = None, content_type: str | None = None) -> bytes:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError("Supabase Storage is not configured.")
    object_path = quote(key, safe="/")
    if method == "GET":
        endpoint = f"{SUPABASE_URL}/storage/v1/object/authenticated/{quote(STORAGE_BUCKET, safe='')}/{object_path}"
    else:
        endpoint = f"{SUPABASE_URL}/storage/v1/object/{quote(STORAGE_BUCKET, safe='')}/{object_path}"
    headers = {"apikey": SUPABASE_SECRET_KEY, "Authorization": f"Bearer {SUPABASE_SECRET_KEY}"}
    if content_type:
        headers["Content-Type"] = content_type
    if method == "POST":
        headers["x-upsert"] = "false"
    req = Request(endpoint, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=25) as response:
            return response.read()
    except HTTPError as exc:
        detail = exc.read(500).decode("utf-8", "replace")
        raise RuntimeError(f"Supabase Storage returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError("Could not reach Supabase Storage.") from exc


def delete_storage_object(key: str) -> None:
    try:
        storage_request("DELETE", key)
    except Exception as exc:
        print(f"Storage cleanup warning: {exc}")


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class Handler(SimpleHTTPRequestHandler):
    server_version = "UrbanEye/1.1"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        super().end_headers()

    def send_json(self, value, status=HTTPStatus.OK, extra_headers=()) -> None:
        def serialize(item):
            if isinstance(item, datetime):
                return item.isoformat()
            if isinstance(item, (bytes, bytearray)):
                return base64.b64encode(item).decode("ascii")
            raise TypeError(f"Cannot JSON encode {type(item).__name__}")
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=serialize).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Request must include a body under 9 MB.")
        try:
            result = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Request body must be valid JSON.")
        if not isinstance(result, dict):
            raise ValueError("Request body must be a JSON object.")
        return result

    def json_body(self):
        try:
            return self.body()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return None

    def origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        expected = os.environ.get("PUBLIC_ORIGIN")
        if expected:
            return origin.rstrip("/") == expected.rstrip("/")
        parsed = urlparse(origin)
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        return bool(parsed.hostname and parsed.hostname.lower() == host)

    def session_user(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get("urbaneye_session")
        if not morsel:
            return None
        with connect() as db:
            row = db.execute(
                "SELECT u.id,u.name,u.email,u.role FROM public.sessions s "
                "JOIN public.users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>%s",
                (token_hash(morsel.value), int(time.time())),
            ).fetchone()
        return dict(row) if row else None

    def require_user(self):
        user = self.session_user()
        if not user:
            self.send_json({"error": "Please sign in to continue."}, HTTPStatus.UNAUTHORIZED)
        return user

    def issue_session(self, user_id: int):
        token = secrets.token_urlsafe(36)
        expiry = int(time.time()) + SESSION_HOURS * 3600
        with connect() as db:
            db.execute("DELETE FROM public.sessions WHERE user_id=%s", (user_id,))
            db.execute(
                "INSERT INTO public.sessions(token_hash,user_id,expires_at,created_at) VALUES(%s,%s,%s,%s)",
                (token_hash(token), user_id, expiry, now_iso()),
            )
        attrs = f"urbaneye_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_HOURS * 3600}"
        if COOKIE_SECURE:
            attrs += "; Secure"
        return ("Set-Cookie", attrs)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            try:
                with connect() as db:
                    db.execute("SELECT 1")
                return self.send_json({"ok": True, "service": "UrbanEye AI"})
            except Exception:
                return self.send_json({"ok": False, "service": "UrbanEye AI"}, HTTPStatus.SERVICE_UNAVAILABLE)
        if path == "/api/session":
            user = self.session_user()
            if not user:
                return self.send_json({"user": None}, HTTPStatus.UNAUTHORIZED)
            return self.send_json({"user": user})
        if path == "/api/reports":
            user = self.require_user()
            if not user:
                return
            with connect() as db:
                rows = db.execute(
                    "SELECT r.id,r.user_id,r.type,r.location,r.area,r.severity,r.description,r.latitude,r.longitude,"
                    "r.image_key,r.status,r.admin_note,r.created_at,r.updated_at,u.name AS reporter_name "
                    "FROM public.reports r JOIN public.users u ON u.id=r.user_id "
                    "WHERE (%s='Administrator' OR r.user_id=%s) ORDER BY r.created_at DESC",
                    (user["role"], user["id"]),
                ).fetchall()
            return self.send_json({"reports": [dict(r) for r in rows]})
        if path.startswith("/api/uploads/"):
            user = self.require_user()
            if not user:
                return
            key = unquote(path.removeprefix("/api/uploads/"))
            if not re.fullmatch(r"[a-f0-9]{32}\.(?:jpg|png|webp)", key):
                return self.send_json({"error": "Image not found."}, HTTPStatus.NOT_FOUND)
            with connect() as db:
                found = db.execute(
                    "SELECT 1 FROM public.reports WHERE image_key=%s AND (%s='Administrator' OR user_id=%s)",
                    (key, user["role"], user["id"]),
                ).fetchone()
            if not found:
                return self.send_json({"error": "Image not found."}, HTTPStatus.NOT_FOUND)
            try:
                data = storage_request("GET", key)
            except Exception:
                return self.send_json({"error": "Could not retrieve report evidence."}, HTTPStatus.BAD_GATEWAY)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mimetypes.guess_type(key)[0] or "application/octet-stream")
            self.send_header("Cache-Control", "private, max-age=300")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
        if not self.origin_ok():
            return self.send_json({"error": "Request origin could not be verified."}, HTTPStatus.FORBIDDEN)
        if path == "/api/auth/register":
            data = self.json_body()
            if data is None:
                return
            name = str(data.get("name", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))
            invite = str(data.get("admin_invite", ""))
            if len(name) < 2 or len(name) > 80 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
                return self.send_json({"error": "Enter a valid name and email address."}, HTTPStatus.BAD_REQUEST)
            if len(password) < 10 or len(password) > 200:
                return self.send_json({"error": "Choose a password with at least 10 characters."}, HTTPStatus.BAD_REQUEST)
            role = "Administrator" if ADMIN_INVITE and hmac.compare_digest(invite, ADMIN_INVITE) else "Citizen"
            salt = secrets.token_bytes(16)
            digest = password_digest(password, salt)
            try:
                with connect() as db:
                    row = db.execute(
                        "INSERT INTO public.users(name,email,password_hash,password_salt,role,created_at) "
                        "VALUES(%s,%s,%s,%s,%s,%s) RETURNING id",
                        (name, email, digest, salt, role, now_iso()),
                    ).fetchone()
                    user_id = row["id"]
            except psycopg.errors.UniqueViolation:
                return self.send_json({"error": "An account with this email already exists."}, HTTPStatus.CONFLICT)
            with connect() as db:
                row = db.execute("SELECT id,name,email,role FROM public.users WHERE id=%s", (user_id,)).fetchone()
            return self.send_json({"user": dict(row)}, HTTPStatus.CREATED, [self.issue_session(user_id)])
        if path == "/api/auth/login":
            forwarded = self.headers.get("X-Forwarded-For", "").strip()
            ip = forwarded.split(",")[-1].strip() if forwarded else self.client_address[0]
            attempts = [t for t in LOGIN_LIMIT.get(ip, []) if t > time.time() - 900]
            if len(attempts) >= 12:
                return self.send_json({"error": "Too many sign-in attempts. Try again in 15 minutes."}, HTTPStatus.TOO_MANY_REQUESTS)
            data = self.json_body()
            if data is None:
                return
            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))
            with connect() as db:
                row = db.execute(
                    "SELECT id,name,email,password_hash,password_salt,role FROM public.users WHERE email=%s",
                    (email,),
                ).fetchone()
            if not row or not hmac.compare_digest(password_digest(password, row["password_salt"]), row["password_hash"]):
                attempts.append(time.time())
                LOGIN_LIMIT[ip] = attempts
                return self.send_json({"error": "Email or password is incorrect."}, HTTPStatus.UNAUTHORIZED)
            LOGIN_LIMIT.pop(ip, None)
            return self.send_json(
                {"user": {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}},
                extra_headers=[self.issue_session(row["id"])],
            )
        if path == "/api/auth/logout":
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get("urbaneye_session")
            if morsel:
                with connect() as db:
                    db.execute("DELETE FROM public.sessions WHERE token_hash=%s", (token_hash(morsel.value),))
            attrs = "urbaneye_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")
            return self.send_json({"ok": True}, extra_headers=[("Set-Cookie", attrs)])
        if path == "/api/reports":
            user = self.require_user()
            if not user:
                return
            data = self.json_body()
            if data is None:
                return
            issue = str(data.get("type", "")).strip()
            location = str(data.get("location", "")).strip()
            area = str(data.get("area", "")).strip()
            severity = str(data.get("severity", "Medium"))
            description = str(data.get("description", "")).strip()
            if not issue or len(issue) > 60 or not location or len(location) > 160 or not area or len(area) > 120 or severity not in {"Low", "Medium", "High"} or len(description) > 2000:
                return self.send_json({"error": "Check the issue, location, area, severity and description fields."}, HTTPStatus.BAD_REQUEST)
            lat = data.get("latitude")
            lon = data.get("longitude")
            try:
                lat = float(lat) if lat not in (None, "") else None
                lon = float(lon) if lon not in (None, "") else None
                if (lat is None) != (lon is None) or (lat is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180)):
                    raise ValueError
            except (TypeError, ValueError):
                return self.send_json({"error": "Enter a valid latitude and longitude pair."}, HTTPStatus.BAD_REQUEST)
            image_key = None
            image_data = data.get("image_data")
            if image_data:
                match = re.fullmatch(r"data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)", str(image_data))
                if not match:
                    return self.send_json({"error": "Use a JPEG, PNG or WebP image."}, HTTPStatus.BAD_REQUEST)
                try:
                    content = base64.b64decode(match.group(2), validate=True)
                except ValueError:
                    return self.send_json({"error": "The uploaded image is not valid."}, HTTPStatus.BAD_REQUEST)
                if not content or len(content) > MAX_IMAGE:
                    return self.send_json({"error": "Images must be under 6 MB."}, HTTPStatus.BAD_REQUEST)
                kind = match.group(1)
                valid = (kind == "jpeg" and content.startswith(b"\xff\xd8\xff")) or (kind == "png" and content.startswith(b"\x89PNG\r\n\x1a\n")) or (kind == "webp" and content.startswith(b"RIFF") and content[8:12] == b"WEBP")
                if not valid:
                    return self.send_json({"error": "The image content does not match its file type."}, HTTPStatus.BAD_REQUEST)
                image_key = uuid.uuid4().hex + {"jpeg": ".jpg", "png": ".png", "webp": ".webp"}[kind]
                try:
                    storage_request("POST", image_key, content, f"image/{kind}")
                except Exception:
                    return self.send_json({"error": "The evidence photo could not be saved. Please try again."}, HTTPStatus.BAD_GATEWAY)
            report_id = "UE-" + uuid.uuid4().hex[:8].upper()
            timestamp = now_iso()
            try:
                with connect() as db:
                    db.execute(
                        "INSERT INTO public.reports(id,user_id,type,location,area,severity,description,latitude,longitude,image_key,status,created_at,updated_at) "
                        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Pending',%s,%s)",
                        (report_id, user["id"], issue, location, area, severity, description, lat, lon, image_key, timestamp, timestamp),
                    )
                    db.execute(
                        "INSERT INTO public.status_history(report_id,user_id,old_status,new_status,created_at) "
                        "VALUES(%s,%s,%s,%s,%s)",
                        (report_id, user["id"], "New", "Pending", timestamp),
                    )
            except Exception:
                if image_key:
                    delete_storage_object(image_key)
                raise
            return self.send_json({"id": report_id, "status": "Pending"}, HTTPStatus.CREATED)
        return self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)

    def do_PATCH(self):
        match = re.fullmatch(r"/api/reports/([A-Z0-9-]+)", urlparse(self.path).path)
        if not match:
            return self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
        if not self.origin_ok():
            return self.send_json({"error": "Request origin could not be verified."}, HTTPStatus.FORBIDDEN)
        user = self.require_user()
        if not user:
            return
        if user["role"] != "Administrator":
            return self.send_json({"error": "Only administrators can change report status."}, HTTPStatus.FORBIDDEN)
        data = self.json_body()
        if data is None:
            return
        status = str(data.get("status", ""))
        note = str(data.get("admin_note", "")).strip()
        if status not in STATUSES or len(note) > 2000:
            return self.send_json({"error": "Choose a valid report status and keep remarks under 2,000 characters."}, HTTPStatus.BAD_REQUEST)
        report_id = match.group(1)
        with connect() as db:
            row = db.execute("SELECT status FROM public.reports WHERE id=%s", (report_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Report not found."}, HTTPStatus.NOT_FOUND)
            timestamp = now_iso()
            if row["status"] != status:
                db.execute(
                    "INSERT INTO public.status_history(report_id,user_id,old_status,new_status,note,created_at) VALUES(%s,%s,%s,%s,%s,%s)",
                    (report_id, user["id"], row["status"], status, note, timestamp),
                )
            db.execute(
                "UPDATE public.reports SET status=%s,admin_note=%s,updated_at=%s WHERE id=%s",
                (status, note, timestamp, report_id),
            )
        return self.send_json({"ok": True, "id": report_id, "status": status})

    def do_DELETE(self):
        if urlparse(self.path).path.startswith("/api/"):
            return self.send_json({"error": "Reports are retained for an audit trail."}, HTTPStatus.METHOD_NOT_ALLOWED)
        return self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)


def main() -> None:
    initialize()
    print(f"UrbanEye AI listening on {HOST}:{PORT}")
    print("Supabase Postgres and private Storage are configured.")
    if not ADMIN_INVITE:
        print("Admin accounts are disabled. Set URBANEYE_ADMIN_INVITE to enable administrator registration.")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UrbanEye AI.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
