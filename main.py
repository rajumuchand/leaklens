import hmac
import hashlib
import time
import re
import io
import os
import json
import base64
import secrets
from typing import Optional
import jwt
import requests as http_requests
from fastapi import FastAPI, HTTPException, Header, Request, UploadFile, File, Form
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, Response, StreamingResponse, RedirectResponse
from pydantic import BaseModel
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = FastAPI(
    title="LeakLens Engine",
    description="Redundant Forensic Watermarking & Enterprise Offline DRM (leaklens)",
    version="3.0.0"
)

# Enable Full CORS Middleware for Firebase Hosting, Framer, and Vercel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


def _get_forwarded_proto(request: Request) -> str:
    """Resolves original client protocol from X-Forwarded-Proto behind cloud HTTPS proxies."""
    raw_proto = request.headers.get("x-forwarded-proto") or request.headers.get("x-forwarded-scheme")
    if raw_proto:
        return raw_proto.split(",")[0].strip().lower()
    return request.url.scheme


@app.middleware("http")
async def https_forwarded_header_middleware(request: Request, call_next):
    """Propagates X-Forwarded-Proto across ASGI scope behind cloud HTTPS proxies."""
    proto = _get_forwarded_proto(request)
    if proto in ("http", "https"):
        request.scope["scheme"] = proto
    request.state.forwarded_proto = proto

    response = await call_next(request)
    response.headers["X-Resolved-Proto"] = proto
    return response

def _load_local_env_files() -> None:
    """Loads .env and .env.local key=value pairs locally if not already in os.environ."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for filename in (".env", ".env.local"):
        path = os.path.join(base_dir, filename)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = val
        except Exception:
            pass


_load_local_env_files()

SECRET_KEY = b"synapse_hackathon_secret_2026"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com")
ALLOWED_GOOGLE_CLIENT_IDS = {
    cid.strip()
    for cid in [
        GOOGLE_CLIENT_ID,
        "243029529822-mkj5hefpohh86e5ru9fdkatve05bubaq.apps.googleusercontent.com",
        "81725914024-6s088pnfsi11jl8tug105mec0pguh3be.apps.googleusercontent.com",
        os.environ.get("FRAMER_GOOGLE_CLIENT_ID", ""),
    ]
    if cid and not cid.startswith("YOUR_GOOGLE_CLIENT_ID")
}
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "synapse_jwt_secret_key_2026")
ALGORITHM = "HS256"
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "leaklens-77637")

SUPABASE_PROJECT_REF = "fpidtcofamgfyyiwyshy"
SUPABASE_URL = (
    os.environ.get("SUPABASE_URL")
    or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
    or f"https://{SUPABASE_PROJECT_REF}.supabase.co"
).rstrip("/")
SUPABASE_PUBLISHABLE_KEY = (
    os.environ.get("SUPABASE_PUBLISHABLE_KEY")
    or os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
    or "sb_publishable_g4OZs168BBOG7KkUOAj1ng_ZCHTXmBY"
)
SUPABASE_ANON_KEY = (
    os.environ.get("SUPABASE_ANON_KEY")
    or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZwaWR0Y29mYW1nZnl5aXd5c2h5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTU1MDI2ODQsImV4cCI6MjExMTA3ODY4NH0.s6p3Gsf_mEYih_rMnpNdDj-6t56Ws36xTEQgH-iyvp0"
)
SUPABASE_SERVICE_ROLE_KEY = (
    os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    or os.environ.get("SUPABASE_SECRET_KEY")
    or ""
)

DEFAULT_CONFIDENTIAL_DOCS = [
    {
        "slug": "helios-brief",
        "title": "Project Helios — Executive M&A Valuation Brief",
        "classification": "STRICTLY CONFIDENTIAL",
        "content": (
            "CONFIDENTIAL M&A VALUATION BRIEF: Project Helios buyout ceiling is set at $142M for Q1 2027.\n"
            "Executive committee approval remains strictly embargoed until Monday market open.\n"
            "Unauthorized external sharing violates Section 4 NDA terms and triggers immediate revocation."
        ),
    },
    {
        "slug": "security-audit",
        "title": "SentinelTrace — Q4 Zero-Trust Security Audit",
        "classification": "INTERNAL RESTRICTED",
        "content": (
            "CONFIDENTIAL SECURITY AUDIT BRIEF: All ephemeral AES-256-GCM decryption keys rotate via hardware monotonic counters.\n"
            "Zero plaintext remnants persist to disk across disconnected sessions.\n"
            "Forensic attribution payloads survive arbitrary snippet truncation above 10% text recovery."
        ),
    },
    {
        "slug": "nda-addendum",
        "title": "Board Committee — Strategic Distribution Addendum",
        "classification": "EYES ONLY",
        "content": (
            "CONFIDENTIAL DISTRIBUTION ADDENDUM: Every distributed copy carries redundant zero-width cryptographic chunks.\n"
            "Extracted leak fragments verify against HMAC-SHA256 signatures even after editing.\n"
            "Revoked sessions overwrite decryption buffers instantaneously with zeroed byte blocks."
        ),
    },
]


class SupabaseRestStore:
    """
    Lightweight Supabase PostgREST + Auth REST integration for LeakLens.
    - Uses SUPABASE_SERVICE_ROLE_KEY on the server when configured.
    - Uses verified user Supabase JWT + publishable key when authenticated via Supabase Auth.
    - Never exposes secret keys and gracefully falls back if disconnected.
    """

    def __init__(self, url: str, publishable_key: str, anon_key: str, service_role_key: str = ""):
        self.url = url.rstrip("/")
        self.publishable_key = publishable_key
        self.anon_key = anon_key
        self.service_role_key = service_role_key
        self.session = http_requests.Session()

    @property
    def has_service_role(self) -> bool:
        return bool(self.service_role_key)

    def _headers(self, user_jwt: Optional[str] = None, allow_public: bool = False) -> Optional[dict]:
        if user_jwt:
            return {
                "apikey": self.publishable_key,
                "Authorization": f"Bearer {user_jwt}",
                "Content-Type": "application/json",
            }
        if self.service_role_key:
            return {
                "apikey": self.service_role_key,
                "Authorization": f"Bearer {self.service_role_key}",
                "Content-Type": "application/json",
            }
        if allow_public and self.publishable_key:
            return {
                "apikey": self.publishable_key,
                "Content-Type": "application/json",
            }
        return None

    def verify_user_jwt(self, user_jwt: str) -> Optional[dict]:
        if not user_jwt:
            return None
        try:
            resp = self.session.get(
                f"{self.url}/auth/v1/user",
                headers={
                    "apikey": self.publishable_key or self.anon_key,
                    "Authorization": f"Bearer {user_jwt}",
                },
                timeout=4,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def sign_up_password(self, email: str, password: str, name: str = "") -> tuple[int, dict]:
        try:
            resp = self.session.post(
                f"{self.url}/auth/v1/signup",
                headers={
                    "apikey": self.publishable_key or self.anon_key,
                    "Content-Type": "application/json",
                },
                json={"email": email, "password": password, "data": {"name": name or email.split("@")[0]}},
                timeout=6,
            )
            return resp.status_code, resp.json()
        except Exception as exc:
            return 503, {"error_description": f"Supabase Auth unreachable: {exc}"}

    def sign_in_password(self, email: str, password: str) -> tuple[int, dict]:
        try:
            resp = self.session.post(
                f"{self.url}/auth/v1/token?grant_type=password",
                headers={
                    "apikey": self.publishable_key or self.anon_key,
                    "Content-Type": "application/json",
                },
                json={"email": email, "password": password},
                timeout=6,
            )
            return resp.status_code, resp.json()
        except Exception as exc:
            return 503, {"error_description": f"Supabase Auth unreachable: {exc}"}

    def fetch_confidential_documents(self, user_jwt: Optional[str] = None) -> list[dict]:
        hdrs = self._headers(user_jwt=user_jwt, allow_public=True)
        if not hdrs:
            return DEFAULT_CONFIDENTIAL_DOCS
        try:
            resp = self.session.get(
                f"{self.url}/rest/v1/confidential_documents",
                headers=hdrs,
                params={"select": "slug,title,classification,content", "order": "id.asc"},
                timeout=4,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if isinstance(rows, list) and rows:
                    return rows
        except Exception:
            pass
        return DEFAULT_CONFIDENTIAL_DOCS

    def fetch_latest_heartbeat(self) -> Optional[dict]:
        hdrs = self._headers(allow_public=True)
        if not hdrs:
            return None
        try:
            resp = self.session.get(
                f"{self.url}/rest/v1/service_heartbeats",
                headers=hdrs,
                params={"select": "id,source,status,created_at", "order": "id.desc", "limit": "1"},
                timeout=4,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if isinstance(rows, list) and rows:
                    return rows[0]
        except Exception:
            pass
        return None

    def record_watermark(self, row: dict, user_jwt: Optional[str] = None) -> bool:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return False
        hdrs["Prefer"] = "return=minimal"
        try:
            resp = self.session.post(f"{self.url}/rest/v1/watermark_records", headers=hdrs, json=row, timeout=4)
            return resp.status_code in (200, 201, 204)
        except Exception:
            return False

    def lookup_homoglyph_signature(self, signature: str, user_jwt: Optional[str] = None) -> Optional[dict]:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return None
        try:
            resp = self.session.get(
                f"{self.url}/rest/v1/watermark_records",
                headers=hdrs,
                params={
                    "select": "recipient_id,session_id,signature,sig_bits,full_bits",
                    "signature": f"eq.{signature}",
                    "order": "id.desc",
                    "limit": "1",
                },
                timeout=4,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if rows:
                    return rows[0]
        except Exception:
            pass
        return None

    def fetch_recent_homoglyph_records(self, limit: int = 50, user_jwt: Optional[str] = None) -> list[dict]:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return []
        try:
            resp = self.session.get(
                f"{self.url}/rest/v1/watermark_records",
                headers=hdrs,
                params={
                    "select": "recipient_id,session_id,signature,sig_bits,full_bits",
                    "full_bits": "not.is.null",
                    "order": "id.desc",
                    "limit": str(limit),
                },
                timeout=4,
            )
            if resp.status_code == 200:
                return resp.json() or []
        except Exception:
            pass
        return []

    def record_inspection(self, row: dict, user_jwt: Optional[str] = None) -> bool:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return False
        hdrs["Prefer"] = "return=minimal"
        try:
            resp = self.session.post(f"{self.url}/rest/v1/leak_inspections", headers=hdrs, json=row, timeout=4)
            return resp.status_code in (200, 201, 204)
        except Exception:
            return False

    def upsert_drm_lease(self, row: dict, user_jwt: Optional[str] = None) -> bool:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return False
        hdrs["Prefer"] = "resolution=merge-duplicates,return=minimal"
        try:
            resp = self.session.post(
                f"{self.url}/rest/v1/drm_leases?on_conflict=lease_id",
                headers=hdrs,
                json=row,
                timeout=4,
            )
            return resp.status_code in (200, 201, 204)
        except Exception:
            return False

    def get_drm_lease(self, lease_id: str, user_jwt: Optional[str] = None) -> Optional[dict]:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return None
        try:
            resp = self.session.get(
                f"{self.url}/rest/v1/drm_leases",
                headers=hdrs,
                params={"select": "*", "lease_id": f"eq.{lease_id}", "limit": "1"},
                timeout=4,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if rows:
                    return rows[0]
        except Exception:
            pass
        return None

    def update_drm_lease(self, lease_id: str, patch: dict, user_jwt: Optional[str] = None) -> bool:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return False
        hdrs["Prefer"] = "return=minimal"
        patch_payload = {**patch, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        try:
            resp = self.session.patch(
                f"{self.url}/rest/v1/drm_leases",
                headers=hdrs,
                params={"lease_id": f"eq.{lease_id}"},
                json=patch_payload,
                timeout=4,
            )
            return resp.status_code in (200, 204)
        except Exception:
            return False

    def create_qr_challenge(self, row: dict, user_jwt: Optional[str] = None) -> bool:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return False
        hdrs["Prefer"] = "return=minimal"
        try:
            resp = self.session.post(f"{self.url}/rest/v1/qr_challenges", headers=hdrs, json=row, timeout=4)
            return resp.status_code in (200, 201, 204)
        except Exception:
            return False

    def consume_qr_challenge(self, challenge_code: str, user_jwt: Optional[str] = None) -> Optional[dict]:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return None
        hdrs["Prefer"] = "return=representation"
        try:
            resp = self.session.patch(
                f"{self.url}/rest/v1/qr_challenges",
                headers=hdrs,
                params={"challenge_code": f"eq.{challenge_code}", "consumed": "eq.false"},
                json={"consumed": True},
                timeout=4,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if rows:
                    return rows[0]
        except Exception:
            pass
        return None

    def fetch_audit_summary(self, user_jwt: Optional[str] = None) -> dict:
        hdrs = self._headers(user_jwt=user_jwt)
        if not hdrs:
            return {
                "connected": bool(self.url),
                "writable": False,
                "auth_mode": "publishable_only",
                "watermarks": [],
                "leases": [],
                "inspections": [],
            }
        result = {
            "connected": True,
            "writable": True,
            "auth_mode": "user_jwt_rls" if user_jwt else "service_role",
            "watermarks": [],
            "leases": [],
            "inspections": [],
        }
        try:
            for key, table, sel in (
                ("watermarks", "watermark_records", "id,recipient_id,session_id,signature,source_type,chunks_embedded,created_at"),
                ("leases", "drm_leases", "id,lease_id,recipient_id,duration_seconds,revoked,tamper_detected,ram_wiped,created_at"),
                ("inspections", "leak_inspections", "id,source,match_found,verified,recipient_id,session_id,signature,recovery_mode,created_at"),
            ):
                resp = self.session.get(
                    f"{self.url}/rest/v1/{table}",
                    headers=hdrs,
                    params={"select": sel, "order": "id.desc", "limit": "8"},
                    timeout=4,
                )
                if resp.status_code == 200:
                    result[key] = resp.json() or []
        except Exception:
            pass
        return result


supabase_store = SupabaseRestStore(
    url=SUPABASE_URL,
    publishable_key=SUPABASE_PUBLISHABLE_KEY,
    anon_key=SUPABASE_ANON_KEY,
    service_role_key=SUPABASE_SERVICE_ROLE_KEY,
)


def _extract_supabase_ctx(request: Optional[Request]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extracts optional X-Supabase-Token from request and resolves verified (token, owner_id, owner_email)."""
    if request is None:
        return None, None, None
    sb_token = (request.headers.get("x-supabase-token") or "").strip()
    if not sb_token:
        return None, None, None
    user_info = supabase_store.verify_user_jwt(sb_token)
    if not user_info:
        return None, None, None
    return sb_token, user_info.get("id"), user_info.get("email")

# Master RSA-2048 Keypair for Cryptographically Signed RS256 .lease Tickets
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()

# Zero-Width Unicode Constants
ZW_0 = "\u200b"      # Zero-Width Space (binary 0)
ZW_1 = "\u200c"      # Zero-Width Non-Joiner (binary 1)
ZW_DELIM = "\u200d"  # Zero-Width Joiner (delimiter)


# --- Enterprise Offline DRM Engine (Monotonic + AES-256-GCM RAM Buffer + RS256) ---

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


class MonotonicDRMLease:
    """
    Enterprise Offline DRM Enforcer:
    1. Anti-Clock-Tampering via relative hardware monotonic ticks (time.monotonic())
    2. Ephemeral In-Memory Decryption using AES-256-GCM with zero disk footprint
    3. Immediate RAM zero-fill key overwrite upon expiration, revocation, or tampering
    """

    def __init__(self, lease_id: str, recipient_id: str, device_hwid: str, duration_seconds: float, document_text: str):
        self.lease_id = lease_id
        self.recipient_id = recipient_id
        self.device_hwid = device_hwid
        self.device_fingerprint = hashlib.sha256(device_hwid.encode("utf-8")).hexdigest()
        self.start_ticks = time.monotonic()
        self.issued_wall = time.time()
        self.duration_seconds = float(duration_seconds)
        self.revoked = False
        self.tamper_detected = False

        # Ephemeral AES-256-GCM Encryption strictly in RAM (zero disk footprint)
        raw_key = AESGCM.generate_key(bit_length=256)
        self.aes_key_buf = bytearray(raw_key)
        self.nonce = os.urandom(12)
        aesgcm = AESGCM(bytes(self.aes_key_buf))
        self.ciphertext = aesgcm.encrypt(self.nonce, document_text.encode("utf-8"), None)

        # Decrypt directly into mutable RAM buffer while lease is active
        decrypted_bytes = aesgcm.decrypt(self.nonce, self.ciphertext, None)
        self.ram_plaintext_buf = bytearray(decrypted_bytes)
        self.ram_wiped = False

    def zero_fill_wipe(self) -> None:
        """Overwrites AES-256 key material and plaintext buffer in RAM with 0x00."""
        if not self.ram_wiped:
            for i in range(len(self.aes_key_buf)):
                self.aes_key_buf[i] = 0
            for i in range(len(self.ram_plaintext_buf)):
                self.ram_plaintext_buf[i] = 0
            self.ram_wiped = True

    def revoke(self, tamper: bool = False) -> None:
        self.revoked = True
        if tamper:
            self.tamper_detected = True
        self.zero_fill_wipe()

    def get_ram_key_preview(self) -> str:
        prefix = bytes(self.aes_key_buf[:4]).hex().upper()
        suffix = bytes(self.aes_key_buf[-2:]).hex().upper()
        return f"0x{prefix}...{suffix}" if not self.ram_wiped else "0x00000000...0000 (ZEROED)"

    def get_viewport_text(self) -> Optional[str]:
        if self.ram_wiped or self.revoked or self.tamper_detected:
            return None
        return bytes(self.ram_plaintext_buf).decode("utf-8", errors="ignore")

    def is_lease_valid(self, client_elapsed_seconds: Optional[float] = None) -> dict:
        server_elapsed = time.monotonic() - self.start_ticks
        elapsed = max(server_elapsed, client_elapsed_seconds or 0.0)
        remaining = self.duration_seconds - elapsed
        valid = (remaining > 0) and (not self.revoked) and (not self.tamper_detected)
        if not valid:
            self.zero_fill_wipe()
        return {
            "valid": valid,
            "remaining_seconds": max(0, int(remaining)) if valid else 0,
            "elapsed_seconds": round(elapsed, 2),
            "ram_wiped": self.ram_wiped,
            "ram_key_preview": self.get_ram_key_preview(),
        }


def issue_rsa_lease_jwt(lease: MonotonicDRMLease) -> tuple[str, dict]:
    """Issues an RSA-256 (RS256) signed JWT & structured .lease envelope."""
    header = {"alg": "RS256", "typ": "JWT", "kid": "sentinel-master-rsa-2048"}
    envelope = {
        "Lease_ID": lease.lease_id,
        "Recipient_ID": lease.recipient_id,
        "Device_Label": lease.device_hwid,
        "Device_Fingerprint": f"sha256:{lease.device_fingerprint[:24]}",
        "Offline_Window_Seconds": int(lease.duration_seconds),
        "Issued_At_UTC": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(lease.issued_wall)),
        "Cipher_Suite": "AES-256-GCM (RAM Ephemeral)",
    }
    signing_input = f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(envelope, separators=(',', ':')).encode())}"
    sig_bytes = RSA_PRIVATE_KEY.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = _b64url_encode(sig_bytes)
    jwt_token = f"{signing_input}.{sig_b64}"
    envelope["Signature"] = f"RS256:{sig_b64[:32]}..."
    return jwt_token, envelope


def verify_rsa_lease_jwt(jwt_token: str) -> Optional[dict]:
    """Verifies RS256 signature using Master RSA Public Key."""
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        sig_bytes = _b64url_decode(parts[2])
        RSA_PUBLIC_KEY.verify(
            sig_bytes,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None


# Server-side monotonic lease ledger & homoglyph attribution ledger (in-memory)
LEASE_REGISTRY: dict[str, MonotonicDRMLease] = {}
QR_CHALLENGES: dict[str, dict] = {}
HOMOGLYPH_LEDGER: dict[str, dict] = {}
HOMOGLYPH_SPACE = "\u00a0"  # Non-Breaking Space homoglyph (binary 1 in space channel)
HOMOGLYPH_SYNC = "101101"   # 6-bit sync preamble before 32-bit signature digest


# --- Cryptographic & Steganography Core ---

def str_to_bits(s: str) -> str:
    return ''.join(format(ord(c), '08b') for c in s)


def bits_to_str(b: str) -> str:
    chars = [b[i:i+8] for i in range(0, len(b), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if len(c) == 8)


def create_hmac(payload: str, key: bytes = SECRET_KEY) -> str:
    return hmac.new(key, payload.encode('utf-8'), hashlib.sha256).hexdigest()[:8]


def create_lease_hmac(payload: str, key: bytes = SECRET_KEY) -> str:
    return hmac.new(key, payload.encode('utf-8'), hashlib.sha256).hexdigest()[:16]


def build_zw_payload(recipient_id: str, session_id: str) -> tuple[str, str]:
    """Creates the invisible zero-width sequence with HMAC-SHA256 signature."""
    payload = f"{recipient_id}|{session_id}"
    signature = create_hmac(payload)
    full_payload = f"{payload}|{signature}"
    bits = str_to_bits(full_payload)
    zw_seq = ZW_DELIM + ''.join(ZW_1 if bit == '1' else ZW_0 for bit in bits) + ZW_DELIM
    return zw_seq, signature


def _apply_homoglyph_space_watermark(text: str, recipient_id: str, session_id: str, signature: str) -> str:
    """
    Secondary Steganographic Fallback Channel:
    Encodes a cyclic 38-bit sequence (6-bit sync + 32-bit HMAC signature digest) across
    interior word spaces using standard ASCII space (0) vs non-breaking space \\u00a0 (1).
    Leaves spaces immediately after sentence punctuation intact so sentence splitting preserves chunks.
    """
    sig_bits = format(int(signature, 16), "032b")
    full_bits = HOMOGLYPH_SYNC + sig_bits
    HOMOGLYPH_LEDGER[signature] = {
        "recipient_id": recipient_id,
        "session_id": session_id,
        "signature": signature,
        "sig_bits": sig_bits,
        "full_bits": full_bits,
    }

    bit_idx = 0

    def _swap_space(match):
        nonlocal bit_idx
        bit = full_bits[bit_idx % len(full_bits)]
        bit_idx += 1
        return match.group(1) + (HOMOGLYPH_SPACE if bit == "1" else " ")

    return re.sub(r"([A-Za-z0-9][\u200b\u200c\u200d]*) (?=[A-Za-z0-9])", _swap_space, text)


def _persist_watermark(
    recipient_id: str,
    session_id: str,
    signature: str,
    source_type: str,
    chunks_embedded: int,
    filename: Optional[str] = None,
    request: Optional[Request] = None,
) -> bool:
    """Persists watermark ledger row & homoglyph signature bits to Supabase cleanly."""
    sb_token, owner_id, owner_email = _extract_supabase_ctx(request)
    sig_bits = format(int(signature, 16), "032b") if re.fullmatch(r"[0-9a-fA-F]{1,8}", signature or "") else ""
    full_bits = (HOMOGLYPH_SYNC + sig_bits) if sig_bits else ""
    row = {
        "signature": signature,
        "recipient_id": recipient_id,
        "session_id": session_id,
        "source_type": source_type,
        "chunks_embedded": max(0, int(chunks_embedded)),
    }
    if filename:
        row["filename"] = filename
    if sig_bits:
        row["sig_bits"] = sig_bits
    if full_bits:
        row["full_bits"] = full_bits
    if owner_id:
        row["owner_id"] = owner_id
    if owner_email:
        row["owner_email"] = owner_email
    return supabase_store.record_watermark(row, user_jwt=sb_token)


def _persist_inspection(res: dict, source_label: str, request: Optional[Request] = None) -> bool:
    """Records forensic leak inspection outcomes into Supabase leak_inspections."""
    sb_token, owner_id, owner_email = _extract_supabase_ctx(request)
    row = {
        "source": res.get("source") or source_label,
        "match_found": bool(res.get("match_found")),
        "verified": bool(res.get("verified")),
        "recipient_id": res.get("recipient_id"),
        "session_id": res.get("session_id"),
        "signature": res.get("signature"),
        "recovery_mode": res.get("recovery_mode"),
        "chunks_detected": int(res.get("chunks_detected") or 0),
        "chunks_verified": int(res.get("chunks_verified") or 0),
        "vector_layer_found": bool(res.get("vector_layer_found")),
        "homoglyph_trace_detected": bool(res.get("homoglyph_trace_detected")),
    }
    if owner_id:
        row["owner_id"] = owner_id
    if owner_email:
        row["owner_email"] = owner_email
    return supabase_store.record_inspection(row, user_jwt=sb_token)


def _decode_homoglyph_fallback(leaked_text: str, user_jwt: Optional[str] = None) -> Optional[dict]:
    """Recovers forensic attribution from homoglyph word-spacing patterns when zero-width chars are stripped."""
    if HOMOGLYPH_SPACE not in leaked_text:
        return None
    space_matches = list(re.finditer(r"(?<=[A-Za-z0-9])[ \u00a0](?=[A-Za-z0-9])", leaked_text))
    if len(space_matches) < 8:
        return None

    extracted_bits = "".join("1" if m.group(0) == HOMOGLYPH_SPACE else "0" for m in space_matches)

    # 1. Exact sync header + 32-bit HMAC digest scan (memory + Supabase fallback)
    idx = extracted_bits.find(HOMOGLYPH_SYNC)
    while idx != -1 and idx + 38 <= len(extracted_bits):
        candidate_sig_bits = extracted_bits[idx + 6 : idx + 38]
        candidate_sig = f"{int(candidate_sig_bits, 2):08x}"
        entry = HOMOGLYPH_LEDGER.get(candidate_sig) or supabase_store.lookup_homoglyph_signature(
            candidate_sig, user_jwt=user_jwt
        )
        if entry:
            HOMOGLYPH_LEDGER[candidate_sig] = entry
            return {
                "recipient_id": entry["recipient_id"],
                "session_id": entry["session_id"],
                "signature": entry["signature"],
                "verified": True,
                "chunks_detected": 1,
                "chunks_verified": 1,
                "recovery_mode": "homoglyph_space_fallback",
                "homoglyph_trace_detected": True,
            }
        idx = extracted_bits.find(HOMOGLYPH_SYNC, idx + 1)

    # 2. Cyclic partial-snippet alignment against issued homoglyph signatures (>= 12 spaces)
    candidates = list(HOMOGLYPH_LEDGER.values())
    if not candidates:
        candidates = supabase_store.fetch_recent_homoglyph_records(limit=50, user_jwt=user_jwt)
    if len(extracted_bits) >= 12 and candidates:
        best_entry = None
        best_score = 0.0
        for entry in candidates:
            cyc = entry.get("full_bits") or ""
            n = len(cyc)
            if not n:
                continue
            for offset in range(n):
                matches = sum(1 for i, b in enumerate(extracted_bits) if b == cyc[(offset + i) % n])
                ratio = matches / len(extracted_bits)
                if ratio > best_score:
                    best_score = ratio
                    best_entry = entry
        if best_entry and best_score >= 0.92:
            return {
                "recipient_id": best_entry["recipient_id"],
                "session_id": best_entry["session_id"],
                "signature": best_entry["signature"],
                "verified": True,
                "chunks_detected": 1,
                "chunks_verified": 1,
                "recovery_mode": "homoglyph_partial_fallback",
                "homoglyph_trace_detected": True,
            }
    return None


def encode_watermark_text_redundant(text: str, recipient_id: str, session_id: str, chunk_words: int = 12) -> tuple[str, int, str]:
    """
    Redundant Chunking & Homoglyph Watermarker:
    1. Embeds zero-width binary sequences (\\u200b, \\u200c, \\u200d) at every sentence,
       paragraph, punctuation mark (.,;:!?—), and word-interval checkpoint.
    2. Injects a secondary homoglyph space-bit channel (ASCII space vs \\u00a0) so
       attribution survives plain-text zero-width stripping.
    """
    zw_seq, signature = build_zw_payload(recipient_id, session_id)
    paragraphs = text.split("\n")
    chunks_embedded = 0
    out_paragraphs = []

    for para in paragraphs:
        if not para.strip():
            out_paragraphs.append(para)
            continue

        sentences = re.split(r'(?<=[.!?])\s+', para)
        watermarked_sentences = []

        for sent in sentences:
            if not sent.strip():
                continue

            # Inject after internal clause punctuation marks (comma, semicolon, colon, em-dash)
            def _inject_clause_punct(m):
                nonlocal chunks_embedded
                chunks_embedded += 1
                return m.group(1) + zw_seq + m.group(2)

            sent_punct = re.sub(r"([,;:\u2014])(\s+)", _inject_clause_punct, sent)

            words = sent_punct.split(" ")
            # Inject mid-sentence every `chunk_words` words for long sentences
            if len(words) > chunk_words:
                rebuilt_words = []
                for w_idx, w in enumerate(words):
                    rebuilt_words.append(w)
                    if w_idx > 0 and w_idx % chunk_words == 0 and w_idx < len(words) - 1:
                        rebuilt_words[-1] = w + zw_seq
                        chunks_embedded += 1
                sent_body = " ".join(rebuilt_words)
            else:
                sent_body = sent_punct

            # Embed inside sentence before ending punctuation
            if sent_body[-1] in ".!?":
                sent_str = sent_body[:-1] + zw_seq + sent_body[-1]
            else:
                sent_str = sent_body + zw_seq
            chunks_embedded += 1
            watermarked_sentences.append(sent_str)

        para_joined = " ".join(watermarked_sentences) + zw_seq
        chunks_embedded += 1
        out_paragraphs.append(para_joined)

    result_text = "\n".join(out_paragraphs)
    if chunks_embedded == 0:
        result_text = text + zw_seq
        chunks_embedded = 1

    # Layer 2 Homoglyph fallback encoding across interior spaces
    result_text = _apply_homoglyph_space_watermark(result_text, recipient_id, session_id, signature)
    return result_text, chunks_embedded, signature


# Backwards-compatible alias
encode_watermark_text = encode_watermark_text_redundant


def _decode_bit_segment(bits_seq: str) -> Optional[dict]:
    bits = ''.join('1' if c == ZW_1 else '0' for c in bits_seq if c in (ZW_0, ZW_1))
    if len(bits) < 24 or len(bits) % 8 != 0:
        return None
    try:
        decoded = bits_to_str(bits)
        parts = decoded.split("|")
        if len(parts) != 3:
            return None
        recipient_id, session_id, extracted_sig = parts
        expected_sig = create_hmac(f"{recipient_id}|{session_id}")
        return {
            "recipient_id": recipient_id,
            "session_id": session_id,
            "signature": extracted_sig,
            "verified": hmac.compare_digest(extracted_sig, expected_sig),
        }
    except Exception:
        return None


def decode_watermark_text(leaked_text: str, user_jwt: Optional[str] = None) -> dict:
    """
    Partial Snippet Recovery Inspector:
    Scans all zero-width watermark blocks in the leaked excerpt. Even if boundary blocks
    are truncated by slicing 10% of a document, any intact redundant block recovers full
    cryptographic attribution.
    """
    # 1. Exact contiguous block scan (immune to truncated boundary blocks)
    contiguous_blocks = re.findall(f"{ZW_DELIM}([{ZW_0}{ZW_1}]+?){ZW_DELIM}", leaked_text)

    # 2. Fallback scan across filtered ZW stream (handles line breaks inserted mid-block)
    zw_chars = ''.join(c for c in leaked_text if c in (ZW_0, ZW_1, ZW_DELIM))
    stream_blocks = []
    if ZW_DELIM in zw_chars:
        parts = zw_chars.split(ZW_DELIM)
        # Segments strictly bounded by delimiters are indices 1 .. len-2
        if len(parts) >= 3:
            stream_blocks = [seg for seg in parts[1:-1] if len(seg) >= 24]

    candidate_segments = contiguous_blocks if contiguous_blocks else stream_blocks

    if not candidate_segments:
        homoglyph_hit = _decode_homoglyph_fallback(leaked_text, user_jwt=user_jwt)
        if homoglyph_hit:
            return {"match_found": True, **homoglyph_hit}
        return {
            "match_found": False,
            "chunks_detected": 0,
            "chunks_verified": 0,
            "error": "No intact forensic watermark or homoglyph signature detected in excerpt.",
        }

    decoded_matches = []
    for seg in candidate_segments:
        parsed = _decode_bit_segment(seg)
        if parsed:
            decoded_matches.append(parsed)

    if not decoded_matches:
        homoglyph_hit = _decode_homoglyph_fallback(leaked_text, user_jwt=user_jwt)
        if homoglyph_hit:
            return {"match_found": True, **homoglyph_hit}
        return {
            "match_found": False,
            "chunks_detected": len(candidate_segments),
            "chunks_verified": 0,
            "error": "Malformed or truncated payload structure.",
        }

    verified_matches = [m for m in decoded_matches if m["verified"]]
    best = verified_matches[0] if verified_matches else decoded_matches[0]

    return {
        "match_found": True,
        "recipient_id": best["recipient_id"],
        "session_id": best["session_id"],
        "signature": best["signature"],
        "verified": best["verified"],
        "redundancy_chunks_detected": len(decoded_matches),
        "chunks_detected": len(decoded_matches),
        "chunks_verified": len(verified_matches),
        "recovery_mode": "redundant_chunk_recovery" if len(decoded_matches) > 1 else "partial_snippet_recovery",
        "homoglyph_trace_detected": HOMOGLYPH_SPACE in leaked_text,
    }


# --- PDF Multimodal Helpers (reportlab + pypdf) ---

_UNICODE_FONT_NAME = "Helvetica"
for _font_path in (
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
):
    if os.path.exists(_font_path):
        try:
            pdfmetrics.registerFont(TTFont("ArialUnicode", _font_path))
            _UNICODE_FONT_NAME = "ArialUnicode"
            break
        except Exception:
            pass


def watermark_pdf_copy_to_copy(pdf_bytes: bytes, recipient_id: str, session_id: str) -> tuple[bytes, str]:
    """
    Merges an invisible zero-width watermark layer onto the original PDF pages.
    Preserves 100% of the original formatting, images, fonts, and layout while
    preserving exact Unicode zero-width characters via a Unicode TrueType font.
    """
    zw_seq, signature = build_zw_payload(recipient_id, session_id)
    proof_tag = f"SENTINELTRACE_PROOF:{recipient_id}|{session_id}|{signature}"

    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter(clone_from=io.BytesIO(pdf_bytes))

    for page in writer.pages:
        page_width = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        packet = io.BytesIO()
        can = rl_canvas.Canvas(packet, pagesize=(page_width, page_height))
        can.setFillColorRGB(0, 0, 0, alpha=0)
        can.setFont(_UNICODE_FONT_NAME, 1)
        can.drawString(10, 10, f"ST-FORENSIC-TAG {zw_seq}")
        can.drawString(10, 14, proof_tag)
        can.save()

        packet.seek(0)
        overlay_pdf = PdfReader(packet)
        page.merge_page(overlay_pdf.pages[0])

    # Preserve existing metadata and append cryptographic proof fields
    merged_meta = dict(reader.metadata or {})
    merged_meta.update({
        "/Author": recipient_id,
        "/Subject": f"Session: {session_id}",
        "/Keywords": f"HMAC-SHA256:{signature}",
        "/SentinelTraceProof": f"{recipient_id}|{session_id}|{signature}",
    })
    writer.add_metadata(merged_meta)

    output_stream = io.BytesIO()
    writer.write(output_stream)
    return output_stream.getvalue(), signature


def generate_watermarked_pdf_bytes(text: str, recipient_id: str, session_id: str) -> tuple[bytes, str]:
    """
    Creates a downloadable PDF containing:
    1. Clean visual document text (with zero-width watermarked text stream)
    2. An invisible vector layer (0 alpha / micro-font proof tag)
    3. Cryptographically signed PDF Metadata (/Author, /Subject, /Keywords, /SentinelTraceProof)
    """
    watermarked_text, _, signature = encode_watermark_text_redundant(text, recipient_id, session_id)
    proof_tag = f"SENTINELTRACE_PROOF:{recipient_id}|{session_id}|{signature}"

    raw_buf = io.BytesIO()
    c = rl_canvas.Canvas(raw_buf, pagesize=letter)
    width, height = letter

    # Header bar
    c.setFont("Helvetica-Bold", 14)
    c.drawString(54, height - 60, "CONFIDENTIAL DOCUMENT // PROTECTED BY LEAKLENS")
    c.setFont("Helvetica", 9)
    c.drawString(54, height - 76, f"Issued Session: {session_id}  |  Integrity: HMAC-SHA256 Verified")
    c.line(54, height - 84, width - 54, height - 84)

    # Visible document body
    text_obj = c.beginText(54, height - 115)
    text_obj.setFont("Helvetica", 11)
    text_obj.setLeading(16)
    for line in text.split("\n"):
        # Wrap long lines cleanly around ~85 chars
        words = line.split(" ")
        current = ""
        for w in words:
            if len(current) + len(w) + 1 > 85:
                text_obj.textLine(current)
                current = w
            else:
                current = f"{current} {w}".strip()
        text_obj.textLine(current)
    c.drawText(text_obj)

    # Invisible Vector Layer (0.0 alpha + micro text embedded in PDF content stream)
    c.saveState()
    c.setFillAlpha(0.0)
    c.setFont(_UNICODE_FONT_NAME, 1)
    c.drawString(10, 10, proof_tag)
    c.drawString(10, 14, watermarked_text)
    c.restoreState()

    c.showPage()
    c.save()
    raw_buf.seek(0)

    # Inject signed metadata using pypdf
    reader = PdfReader(raw_buf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    writer.add_metadata({
        "/Title": "SentinelTrace Protected Document",
        "/Author": recipient_id,
        "/Subject": f"Session: {session_id}",
        "/Keywords": f"HMAC-SHA256:{signature}",
        "/SentinelTraceProof": f"{recipient_id}|{session_id}|{signature}",
    })

    final_buf = io.BytesIO()
    writer.write(final_buf)
    return final_buf.getvalue(), signature


def inspect_pdf_bytes(pdf_bytes: bytes, user_jwt: Optional[str] = None) -> dict:
    """
    Uses pypdf to extract hidden metadata fields AND invisible vector layers
    from an uploaded PDF, verifying the HMAC-SHA256 signature.
    """
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        return {"match_found": False, "error": f"Invalid PDF file: {str(e)}"}

    meta = reader.metadata or {}
    proof_meta = meta.get("/SentinelTraceProof")
    meta_author = meta.get("/Author")
    meta_subject = meta.get("/Subject")
    meta_keywords = meta.get("/Keywords")

    extracted_text = "\n".join(page.extract_text() or "" for page in reader.pages)

    # Check 1: Invisible Vector Layer proof tag (prefer latest layer or metadata-matching proof)
    vector_matches = re.findall(r"SENTINELTRACE_PROOF:([^\n\r|]+)\|([^\n\r|]+)\|([a-f0-9]{8})", extracted_text)
    vector_layer_found = len(vector_matches) > 0

    if vector_matches:
        chosen = vector_matches[-1]
        if proof_meta:
            for m in reversed(vector_matches):
                if f"{m[0]}|{m[1]}|{m[2]}" == str(proof_meta):
                    chosen = m
                    break
        r_id, s_id, sig = chosen
        expected = create_hmac(f"{r_id}|{s_id}")
        return {
            "match_found": True,
            "source": "PDF Invisible Vector Layer + Metadata" if proof_meta else "PDF Invisible Vector Layer",
            "recipient_id": r_id,
            "session_id": s_id,
            "signature": sig,
            "verified": hmac.compare_digest(sig, expected),
            "metadata_author": meta_author,
            "metadata_subject": meta_subject,
            "vector_layer_found": True,
        }

    # Check 2: Signed /SentinelTraceProof metadata field
    if proof_meta and "|" in str(proof_meta):
        parts = str(proof_meta).split("|")
        if len(parts) == 3:
            r_id, s_id, sig = parts
            expected = create_hmac(f"{r_id}|{s_id}")
            return {
                "match_found": True,
                "source": "PDF Hidden Metadata (/SentinelTraceProof)",
                "recipient_id": r_id,
                "session_id": s_id,
                "signature": sig,
                "verified": hmac.compare_digest(sig, expected),
                "metadata_author": meta_author,
                "metadata_subject": meta_subject,
                "vector_layer_found": False,
            }

    # Check 3: Standard /Author + /Subject + /Keywords metadata
    if meta_author and meta_subject and meta_keywords and "HMAC-SHA256:" in str(meta_keywords):
        s_id = str(meta_subject).replace("Session: ", "").strip()
        sig = str(meta_keywords).replace("HMAC-SHA256:", "").strip()
        expected = create_hmac(f"{meta_author}|{s_id}")
        return {
            "match_found": True,
            "source": "PDF Standard Metadata (/Author, /Subject, /Keywords)",
            "recipient_id": str(meta_author),
            "session_id": s_id,
            "signature": sig,
            "verified": hmac.compare_digest(sig, expected),
            "metadata_author": meta_author,
            "metadata_subject": meta_subject,
            "vector_layer_found": False,
        }

    # Check 4: Zero-width characters embedded inside PDF text stream
    zw_res = decode_watermark_text(extracted_text, user_jwt=user_jwt)
    if zw_res.get("match_found"):
        zw_res["source"] = "PDF Embedded Zero-Width Text Layer"
        zw_res["metadata_author"] = meta_author
        zw_res["metadata_subject"] = meta_subject
        zw_res["vector_layer_found"] = vector_layer_found
        return zw_res

    return {
        "match_found": False,
        "error": "No forensic PDF metadata, vector layer, or zero-width watermark detected.",
        "metadata_author": meta_author,
        "vector_layer_found": False,
    }


# --- Input Request Schemas ---

class WatermarkRequest(BaseModel):
    recipient_id: str
    session_id: str
    text: str


class InspectRequest(BaseModel):
    leaked_text: str


class IssueLeaseRequest(BaseModel):
    duration_seconds: int = 1800
    recipient_id: str = "ALICE SMITH (USR-8492)"
    device_hwid: str = "HWID-84F9-33A1-KEY"
    document_text: str = (
        "CONFIDENTIAL BOARD ACQUISITION MEMO:\n"
        "Project Helios buyout ceiling is set at $142M for Q1 2027. "
        "Decrypted strictly into ephemeral RAM with zero disk cache footprint."
    )


class LeaseRequest(BaseModel):
    permission_end_timestamp: Optional[float] = None
    lease_token: Optional[str] = None
    rsa_jwt: Optional[str] = None
    client_elapsed_seconds: Optional[float] = None
    simulated_clock_offset_seconds: float = 0.0


class RevokeLeaseRequest(BaseModel):
    lease_id: Optional[str] = None
    lease_token: Optional[str] = None


class QrChallengeRequest(BaseModel):
    lease_id: Optional[str] = None
    recipient_id: str = "ALICE SMITH (USR-8492)"
    device_hwid: str = "HWID-84F9-33A1-KEY"
    duration_seconds: int = 1800


class QrCompleteRequest(BaseModel):
    challenge_code: str
    duration_seconds: int = 1800


# --- API Routes ---

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
STATIC_INDEX_PATH = os.path.join(STATIC_DIR, "index.html")
STATIC_LOGIN_PATH = os.path.join(STATIC_DIR, "login.html")
STATIC_MANIFEST_PATH = os.path.join(STATIC_DIR, "manifest.json")
STATIC_SW_PATH = os.path.join(STATIC_DIR, "sw.js")
STATIC_ICONS_DIR = os.path.join(STATIC_DIR, "icons")


@app.get("/")
def root(request: Request):
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header and os.path.exists(STATIC_INDEX_PATH):
        return FileResponse(STATIC_INDEX_PATH)
    return {
        "status": "online",
        "service": "LeakLens Engine",
        "project": "leaklens",
        "version": "3.0.0",
        "scheme": _get_forwarded_proto(request),
    }


@app.get("/index.html")
def serve_index_html():
    if os.path.exists(STATIC_INDEX_PATH):
        return FileResponse(
            STATIC_INDEX_PATH,
            media_type="text/html",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
        )
    return HTMLResponse("<h1>Index not found.</h1>", status_code=404)


@app.get("/manifest.json")
def serve_manifest():
    if os.path.exists(STATIC_MANIFEST_PATH):
        return FileResponse(
            STATIC_MANIFEST_PATH,
            media_type="application/manifest+json",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
        )
    raise HTTPException(status_code=404, detail="Manifest not found.")


@app.get("/sw.js")
def serve_service_worker():
    if os.path.exists(STATIC_SW_PATH):
        return FileResponse(
            STATIC_SW_PATH,
            media_type="application/javascript",
            headers={
                "Cache-Control": "public, max-age=0, must-revalidate",
                "Service-Worker-Allowed": "/",
            },
        )
    raise HTTPException(status_code=404, detail="Service worker not found.")


@app.get("/icons/{icon_name}")
def serve_pwa_icon(icon_name: str):
    allowed = {"apple-touch-icon.png", "icon-192x192.png", "icon-512x512.png"}
    safe_name = os.path.basename(icon_name)
    if safe_name not in allowed:
        raise HTTPException(status_code=404, detail="Icon not found.")
    icon_path = os.path.join(STATIC_ICONS_DIR, safe_name)
    if not os.path.exists(icon_path):
        raise HTTPException(status_code=404, detail="Icon not found.")
    return FileResponse(
        icon_path,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/demo")
def demo_page():
    if os.path.exists(STATIC_INDEX_PATH):
        return FileResponse(STATIC_INDEX_PATH)
    return HTMLResponse("<h1>Demo page not found.</h1>", status_code=404)


@app.get("/login")
def login_page(request: Request):
    from urllib.parse import urlencode
    proto = _get_forwarded_proto(request)
    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "leaklens-omega.vercel.app"
    is_firebase_host = fwd_host.endswith(".web.app") or fwd_host.endswith(".firebaseapp.com")
    if not is_firebase_host:
        q_params = dict(request.query_params)
        if not q_params.get("redirect"):
            q_params["redirect"] = f"{proto}://{fwd_host}/"
        return RedirectResponse(
            url=f"https://leaklens-77637.web.app/login?{urlencode(q_params)}",
            status_code=302,
        )
    if os.path.exists(STATIC_LOGIN_PATH):
        return FileResponse(
            STATIC_LOGIN_PATH,
            media_type="text/html",
            headers={"Cache-Control": "public, max-age=0, must-revalidate"},
        )
    return HTMLResponse("<h1>Login page not found.</h1>", status_code=404)


@app.get("/api/health")
def api_health(request: Request):
    docs = supabase_store.fetch_confidential_documents()
    heartbeat = supabase_store.fetch_latest_heartbeat()
    return {
        "status": "online",
        "service": "LeakLens Engine",
        "project": "leaklens",
        "version": "3.0.0",
        "scheme": _get_forwarded_proto(request),
        "uptime_mode": "24x7 Cloud (Vercel + Supabase Edge + pg_cron + GitHub Actions)",
        "supabase": {
            "project_ref": SUPABASE_PROJECT_REF,
            "url": SUPABASE_URL,
            "edge_function_url": f"{SUPABASE_URL}/functions/v1/leaklens-engine",
            "connected": bool(docs),
            "documents_count": len(docs),
            "service_role_configured": supabase_store.has_service_role,
            "latest_heartbeat": heartbeat,
        },
    }


@app.get("/api/documents")
def list_confidential_documents(request: Request):
    """Fetches confidential documents from Supabase Postgres with built-in offline fallback."""
    sb_token, _, _ = _extract_supabase_ctx(request)
    docs = supabase_store.fetch_confidential_documents(user_jwt=sb_token)
    return {
        "status": "success",
        "source": "supabase",
        "project_ref": SUPABASE_PROJECT_REF,
        "documents": docs,
    }


@app.get("/api/supabase/records")
def get_supabase_audit_records(request: Request):
    """Returns persisted watermark, DRM lease, and leak inspection records for this operator/server."""
    sb_token, _, _ = _extract_supabase_ctx(request)
    return {
        "status": "success",
        "project_ref": SUPABASE_PROJECT_REF,
        **supabase_store.fetch_audit_summary(user_jwt=sb_token),
    }


@app.post("/api/watermark")
def watermark_endpoint(req: WatermarkRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    watermarked_text, chunks_embedded, signature = encode_watermark_text_redundant(
        req.text, req.recipient_id, req.session_id
    )
    persisted = _persist_watermark(
        req.recipient_id, req.session_id, signature, "text", chunks_embedded, request=request
    )
    return {
        "status": "success",
        "recipient_id": req.recipient_id,
        "session_id": req.session_id,
        "signature": signature,
        "chunks_embedded": chunks_embedded,
        "watermarked_text": watermarked_text,
        "supabase_persisted": persisted,
    }


@app.post("/api/inspect")
def inspect_endpoint(req: InspectRequest, request: Request):
    if not req.leaked_text.strip():
        raise HTTPException(status_code=400, detail="Leaked snippet cannot be empty.")

    sb_token, _, _ = _extract_supabase_ctx(request)
    res = decode_watermark_text(req.leaked_text, user_jwt=sb_token)
    res["supabase_persisted"] = _persist_inspection(res, "Text Steganography Inspector", request=request)
    return res


@app.post("/api/watermark-pdf")
async def watermark_pdf_endpoint(
    request: Request,
    file: UploadFile = File(...),
    recipient_id: str = Form("USR-8492-ALICE"),
    session_id: str = Form("SESS-2026")
):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a PDF.")

    contents = await file.read()
    try:
        reader = PdfReader(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid PDF file: {str(e)}")

    extracted_text = ""
    for page in reader.pages:
        text = page.extract_text()
        if text:
            extracted_text += text + "\n"

    if not extracted_text.strip():
        raise HTTPException(status_code=400, detail="Could not extract text from PDF (it may be scanned or empty).")

    watermarked_text, chunks_embedded, signature = encode_watermark_text_redundant(
        extracted_text.strip(), recipient_id, session_id
    )
    persisted = _persist_watermark(
        recipient_id, session_id, signature, "pdf_extract", chunks_embedded, filename=file.filename, request=request
    )

    return {
        "status": "success",
        "filename": file.filename,
        "recipient_id": recipient_id,
        "session_id": session_id,
        "signature": signature,
        "chunks_embedded": chunks_embedded,
        "watermarked_text": watermarked_text,
        "pages_processed": len(reader.pages),
        "supabase_persisted": persisted,
    }


@app.post("/api/download-watermarked-pdf")
async def download_watermarked_pdf(
    request: Request,
    file: UploadFile = File(...),
    recipient_id: str = Form("USR-8492-ALICE"),
    session_id: str = Form("SESS-2026")
):
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="File must be a PDF.")

    contents = await file.read()
    try:
        watermarked_pdf_bytes, signature = watermark_pdf_copy_to_copy(contents, recipient_id, session_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to watermark PDF: {str(e)}")

    _persist_watermark(
        recipient_id, session_id, signature, "pdf_overlay", 1, filename=file.filename, request=request
    )
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", file.filename)
    proto = _get_forwarded_proto(request)
    return StreamingResponse(
        io.BytesIO(watermarked_pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="watermarked_{safe_name}"',
            "X-Sentinel-Signature": signature,
            "X-Sentinel-Recipient": recipient_id,
            "X-Forwarded-Proto-Resolved": proto,
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/export-watermark-pdf")
def export_watermark_pdf_endpoint(req: WatermarkRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    pdf_bytes, signature = generate_watermarked_pdf_bytes(req.text, req.recipient_id, req.session_id)
    _persist_watermark(req.recipient_id, req.session_id, signature, "pdf_export", 1, request=request)
    safe_session = re.sub(r"[^a-zA-Z0-9_-]", "_", req.session_id)
    proto = _get_forwarded_proto(request)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="LeakLens_{safe_session}.pdf"',
            "X-Sentinel-Signature": signature,
            "X-Sentinel-Recipient": req.recipient_id,
            "X-Forwarded-Proto-Resolved": proto,
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/inspect-pdf")
async def inspect_pdf_endpoint(request: Request, file: UploadFile = File(...)):
    pdf_bytes = await file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="Uploaded PDF is empty.")
    sb_token, _, _ = _extract_supabase_ctx(request)
    res = inspect_pdf_bytes(pdf_bytes, user_jwt=sb_token)
    res["supabase_persisted"] = _persist_inspection(res, "PDF Forensic Inspector", request=request)
    return res


@app.post("/api/issue-lease")
def issue_lease_endpoint(req: IssueLeaseRequest, request: Request):
    """
    Issues a hardware-bound, RSA-256 signed lease ticket + AES-256-GCM ephemeral
    RAM decryption buffer anchored to time.monotonic().
    """
    duration = max(1, req.duration_seconds)
    lease_id = secrets.token_hex(6)
    lease = MonotonicDRMLease(
        lease_id=lease_id,
        recipient_id=req.recipient_id,
        device_hwid=req.device_hwid,
        duration_seconds=duration,
        document_text=req.document_text,
    )
    LEASE_REGISTRY[lease_id] = lease

    # Legacy HMAC lease token + full RSA-256 signed JWT & .lease envelope
    payload = f"{lease_id}|{int(lease.issued_wall)}|{duration}"
    sig = create_lease_hmac(payload)
    lease_token = f"{payload}|{sig}"
    rsa_jwt, lease_envelope = issue_rsa_lease_jwt(lease)

    sb_token, owner_id, owner_email = _extract_supabase_ctx(request)
    lease_row = {
        "lease_id": lease_id,
        "recipient_id": lease.recipient_id,
        "device_hwid": lease.device_hwid,
        "device_fingerprint": lease.device_fingerprint[:24],
        "duration_seconds": duration,
        "issued_wall_ts": lease.issued_wall,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(lease.issued_wall + duration)),
        "revoked": False,
        "tamper_detected": False,
        "ram_wiped": False,
        "ram_key_preview": lease.get_ram_key_preview(),
        "rsa_sig_prefix": lease_envelope.get("Signature"),
        "document_preview": (req.document_text or "")[:240],
        "ciphertext_preview": f"AES-256-GCM:{base64.b64encode(lease.ciphertext[:24]).decode()}",
    }
    if owner_id:
        lease_row["owner_id"] = owner_id
    if owner_email:
        lease_row["owner_email"] = owner_email
    persisted = supabase_store.upsert_drm_lease(lease_row, user_jwt=sb_token)

    return {
        "status": "issued",
        "lease_id": lease_id,
        "lease_token": lease_token,
        "rsa_jwt": rsa_jwt,
        "lease_envelope": lease_envelope,
        "device_hwid": lease.device_hwid,
        "device_fingerprint": lease.device_fingerprint[:16],
        "ram_key_status": "AES-256-GCM RAM Key Loaded (Zero Disk Footprint)",
        "ram_key_preview": lease.get_ram_key_preview(),
        "decrypted_viewport_text": lease.get_viewport_text(),
        "issued_at_wall": lease.issued_wall,
        "duration_seconds": duration,
        "permission_end_timestamp": lease.issued_wall + duration,
        "supabase_persisted": persisted,
    }


@app.post("/api/revoke-lease")
def revoke_lease_endpoint(req: RevokeLeaseRequest, request: Request):
    """
    Instant Kill-Switch: Immediately zero-fills AES-256-GCM key & plaintext in RAM and Supabase.
    """
    lease_id = req.lease_id
    if not lease_id and req.lease_token and "|" in req.lease_token:
        lease_id = req.lease_token.split("|")[0]

    sb_token, _, _ = _extract_supabase_ctx(request)
    if lease_id:
        supabase_store.update_drm_lease(
            lease_id,
            {
                "revoked": True,
                "ram_wiped": True,
                "ram_key_preview": "0x00000000...0000 (ZEROED)",
            },
            user_jwt=sb_token,
        )

    lease = LEASE_REGISTRY.get(lease_id) if lease_id else None
    if lease:
        lease.revoke(tamper=False)
        return {
            "status": "revoked",
            "access_allowed": False,
            "ram_wiped": lease.ram_wiped,
            "ram_key_preview": lease.get_ram_key_preview(),
            "decrypted_viewport_text": None,
            "status_message": "ACCESS REVOKED / RAM KEY ZEROED",
        }
    return {
        "status": "revoked",
        "access_allowed": False,
        "ram_wiped": True,
        "ram_key_preview": "0x00000000...0000 (ZEROED)",
        "decrypted_viewport_text": None,
        "status_message": "ACCESS REVOKED / RAM KEY ZEROED",
    }


@app.post("/api/challenge-qr-renewal")
def challenge_qr_renewal_endpoint(req: QrChallengeRequest, request: Request):
    """
    Generates an air-gapped cryptographic QR challenge and persists it in Supabase.
    """
    challenge_code = f"QR-{secrets.token_hex(4).upper()}"
    nonce = secrets.token_hex(8)
    challenge_payload = {
        "challenge": challenge_code,
        "recipient_id": req.recipient_id,
        "device_hwid": req.device_hwid,
        "requested_window_sec": req.duration_seconds,
        "nonce": nonce,
        "rsa_alg": "RS256",
    }
    QR_CHALLENGES[challenge_code] = challenge_payload
    sb_token, owner_id, _ = _extract_supabase_ctx(request)
    row = {
        "challenge_code": challenge_code,
        "recipient_id": req.recipient_id,
        "device_hwid": req.device_hwid,
        "requested_window_sec": max(1, int(req.duration_seconds)),
        "nonce": nonce,
        "consumed": False,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120)),
    }
    if owner_id:
        row["owner_id"] = owner_id
    persisted = supabase_store.create_qr_challenge(row, user_jwt=sb_token)
    return {
        "status": "challenge_ready",
        "challenge_code": challenge_code,
        "qr_payload": json.dumps(challenge_payload),
        "expires_in_seconds": 120,
        "supabase_persisted": persisted,
    }


@app.post("/api/complete-qr-renewal")
def complete_qr_renewal_endpoint(req: QrCompleteRequest, request: Request):
    """Verifies the offline QR challenge code (RAM or Supabase) and issues a fresh Monotonic AES-256-GCM lease."""
    sb_token, _, _ = _extract_supabase_ctx(request)
    challenge = QR_CHALLENGES.pop(req.challenge_code, None)
    if challenge:
        supabase_store.consume_qr_challenge(req.challenge_code, user_jwt=sb_token)
    else:
        db_challenge = supabase_store.consume_qr_challenge(req.challenge_code, user_jwt=sb_token)
        if db_challenge:
            challenge = {
                "recipient_id": db_challenge["recipient_id"],
                "device_hwid": db_challenge["device_hwid"],
            }
    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid or expired QR challenge code.")

    return issue_lease_endpoint(
        IssueLeaseRequest(
            duration_seconds=req.duration_seconds,
            recipient_id=challenge["recipient_id"],
            device_hwid=challenge["device_hwid"],
        ),
        request=request,
    )


@app.post("/api/validate-lease")
def validate_lease_endpoint(req: LeaseRequest, request: Request):
    """
    Enterprise DRM Validation:
    - Verifies RSA-256 JWT or HMAC lease token
    - Evaluates MonotonicDRMLease (time.monotonic() delta) and Supabase revocation ledger
    - Detects OS wall-clock rollbacks and immediately zero-fills AES-256-GCM RAM buffers
    """
    current_wall = time.time()
    sb_token, _, _ = _extract_supabase_ctx(request)
    rsa_verified = False
    rsa_claims = None

    if req.rsa_jwt:
        rsa_claims = verify_rsa_lease_jwt(req.rsa_jwt)
        if not rsa_claims:
            return {
                "access_allowed": False,
                "token_verified": False,
                "rsa_verified": False,
                "clock_tamper_detected": True,
                "ram_wiped": True,
                "ram_key_preview": "0x00000000...0000 (ZEROED)",
                "decrypted_viewport_text": None,
                "remaining_seconds": 0,
                "monotonic_elapsed_seconds": 0,
                "status_message": "ACCESS REVOKED / INVALID RSA-256 SIGNATURE",
            }
        rsa_verified = True

    # Path A: Cryptographic Lease Token + MonotonicDRMLease Enforcement
    if req.lease_token:
        parts = req.lease_token.split("|")
        if len(parts) != 4:
            return {
                "access_allowed": False,
                "token_verified": False,
                "rsa_verified": rsa_verified,
                "clock_tamper_detected": True,
                "ram_wiped": True,
                "ram_key_preview": "0x00000000...0000 (ZEROED)",
                "decrypted_viewport_text": None,
                "remaining_seconds": 0,
                "monotonic_elapsed_seconds": 0,
                "status_message": "ACCESS REVOKED / MALFORMED LEASE TOKEN",
            }

        lease_id, issued_wall_str, duration_str, sig = parts
        expected_sig = create_lease_hmac(f"{lease_id}|{issued_wall_str}|{duration_str}")
        if not hmac.compare_digest(sig, expected_sig):
            return {
                "access_allowed": False,
                "token_verified": False,
                "rsa_verified": rsa_verified,
                "clock_tamper_detected": True,
                "ram_wiped": True,
                "ram_key_preview": "0x00000000...0000 (ZEROED)",
                "decrypted_viewport_text": None,
                "remaining_seconds": 0,
                "monotonic_elapsed_seconds": 0,
                "status_message": "ACCESS REVOKED / FORGED LEASE TOKEN",
            }

        duration = int(duration_str)
        lease = LEASE_REGISTRY.get(lease_id)

        if lease:
            if req.simulated_clock_offset_seconds < -5.0 or lease.tamper_detected:
                lease.revoke(tamper=True)
                supabase_store.update_drm_lease(
                    lease_id,
                    {"revoked": True, "tamper_detected": True, "ram_wiped": True, "ram_key_preview": lease.get_ram_key_preview()},
                    user_jwt=sb_token,
                )
                return {
                    "access_allowed": False,
                    "token_verified": True,
                    "rsa_verified": rsa_verified,
                    "clock_tamper_detected": True,
                    "ram_wiped": lease.ram_wiped,
                    "ram_key_preview": lease.get_ram_key_preview(),
                    "decrypted_viewport_text": None,
                    "device_hwid": lease.device_hwid,
                    "current_time": current_wall + req.simulated_clock_offset_seconds,
                    "permission_end_timestamp": lease.issued_wall + duration,
                    "monotonic_elapsed_seconds": round(time.monotonic() - lease.start_ticks, 2),
                    "remaining_seconds": 0,
                    "status_message": "ACCESS REVOKED / CLOCK TAMPERING DETECTED",
                }

            status = lease.is_lease_valid(req.client_elapsed_seconds)
            if not status["valid"] or lease.revoked:
                lease.zero_fill_wipe()
                status["ram_wiped"] = True
                status["ram_key_preview"] = lease.get_ram_key_preview()
                supabase_store.update_drm_lease(
                    lease_id,
                    {"ram_wiped": True, "ram_key_preview": status["ram_key_preview"]},
                    user_jwt=sb_token,
                )

            if lease.revoked:
                msg = "ACCESS REVOKED / RAM KEY ZEROED"
            elif status["valid"]:
                msg = "ACCESS GRANTED (RAM Key Loaded)"
            else:
                msg = "ACCESS REVOKED / EXPIRED"

            return {
                "access_allowed": status["valid"],
                "token_verified": True,
                "rsa_verified": rsa_verified,
                "clock_tamper_detected": False,
                "ram_wiped": status["ram_wiped"],
                "ram_key_preview": status["ram_key_preview"],
                "decrypted_viewport_text": lease.get_viewport_text() if status["valid"] else None,
                "lockdown_state": "ACTIVE_DECRYPTED_RAM" if status["valid"] else "ENCRYPTED_LOCKDOWN_RAM_WIPED",
                "ciphertext_preview": None if status["valid"] else f"AES-256-GCM:{base64.b64encode(lease.ciphertext[:24]).decode()}...",
                "device_hwid": lease.device_hwid,
                "current_time": current_wall,
                "permission_end_timestamp": lease.issued_wall + duration,
                "monotonic_elapsed_seconds": status["elapsed_seconds"],
                "remaining_seconds": status["remaining_seconds"],
                "status_message": msg,
            }
        else:
            db_lease = supabase_store.get_drm_lease(lease_id, user_jwt=sb_token)
            effective_elapsed = req.client_elapsed_seconds if req.client_elapsed_seconds is not None else max(0.0, current_wall - float(issued_wall_str))
            if db_lease and (db_lease.get("revoked") or db_lease.get("tamper_detected") or db_lease.get("ram_wiped")):
                return {
                    "access_allowed": False,
                    "token_verified": True,
                    "rsa_verified": rsa_verified,
                    "clock_tamper_detected": bool(db_lease.get("tamper_detected")),
                    "ram_wiped": True,
                    "ram_key_preview": db_lease.get("ram_key_preview") or "0x00000000...0000 (ZEROED)",
                    "decrypted_viewport_text": None,
                    "device_hwid": db_lease.get("device_hwid"),
                    "monotonic_elapsed_seconds": round(effective_elapsed, 2),
                    "remaining_seconds": 0,
                    "status_message": "ACCESS REVOKED / CLOCK TAMPERING DETECTED"
                    if db_lease.get("tamper_detected")
                    else "ACCESS REVOKED / RAM KEY ZEROED",
                }
            if req.simulated_clock_offset_seconds < -5.0:
                supabase_store.update_drm_lease(
                    lease_id,
                    {"revoked": True, "tamper_detected": True, "ram_wiped": True, "ram_key_preview": "0x00000000...0000 (ZEROED)"},
                    user_jwt=sb_token,
                )
                return {
                    "access_allowed": False,
                    "token_verified": True,
                    "rsa_verified": rsa_verified,
                    "clock_tamper_detected": True,
                    "ram_wiped": True,
                    "ram_key_preview": "0x00000000...0000 (ZEROED)",
                    "decrypted_viewport_text": None,
                    "monotonic_elapsed_seconds": round(effective_elapsed, 2),
                    "remaining_seconds": 0,
                    "status_message": "ACCESS REVOKED / CLOCK TAMPERING DETECTED",
                }
            remaining = max(0, int(duration - effective_elapsed))
            is_valid = remaining > 0
            return {
                "access_allowed": is_valid,
                "token_verified": True,
                "rsa_verified": rsa_verified,
                "clock_tamper_detected": False,
                "ram_wiped": not is_valid,
                "ram_key_preview": "0x00000000...0000 (ZEROED)" if not is_valid else "0xAES256RAM...ACTIVE",
                "current_time": current_wall,
                "permission_end_timestamp": float(issued_wall_str) + duration,
                "monotonic_elapsed_seconds": round(effective_elapsed, 2),
                "remaining_seconds": remaining,
                "status_message": "ACCESS GRANTED (RAM Key Loaded)" if is_valid else "ACCESS REVOKED / EXPIRED",
            }

    # Path B: Legacy timestamp mode
    if req.simulated_clock_offset_seconds < -5.0:
        return {
            "access_allowed": False,
            "token_verified": False,
            "rsa_verified": rsa_verified,
            "clock_tamper_detected": True,
            "ram_wiped": True,
            "ram_key_preview": "0x00000000...0000 (ZEROED)",
            "decrypted_viewport_text": None,
            "current_time": current_wall + req.simulated_clock_offset_seconds,
            "permission_end_timestamp": req.permission_end_timestamp or current_wall,
            "remaining_seconds": 0,
            "status_message": "ACCESS REVOKED / CLOCK TAMPERING DETECTED",
        }

    end_ts = req.permission_end_timestamp or current_wall
    remaining = end_ts - current_wall
    is_valid = remaining > 0
    return {
        "access_allowed": is_valid,
        "token_verified": False,
        "rsa_verified": rsa_verified,
        "clock_tamper_detected": False,
        "ram_wiped": not is_valid,
        "current_time": current_wall,
        "permission_end_timestamp": end_ts,
        "remaining_seconds": max(0, int(remaining)),
        "status_message": "ACCESS GRANTED (RAM Key Loaded)" if is_valid else "ACCESS REVOKED / EXPIRED",
    }


@app.post("/api/regenerate-demo-copies")
def regenerate_demo_copies(request: Request):
    """Batch endpoint generating visually identical Alice and Bob watermarked copies."""
    base_text = (
        "CONFIDENTIAL INTERNAL MEMO: Project SentinelTrace launch roadmap and "
        "Q4 target metrics must remain internal. Unauthorized sharing or copying "
        "will trigger automated forensic tracing."
    )

    alice_doc, alice_chunks, alice_sig = encode_watermark_text_redundant(
        base_text,
        recipient_id="Alice Smith (USR-8492)",
        session_id="SES-SYNAPSE-2026",
    )

    bob_doc, bob_chunks, bob_sig = encode_watermark_text_redundant(
        base_text,
        recipient_id="Bob Jones (USR-3104)",
        session_id="SES-SYNAPSE-2026",
    )

    _persist_watermark("Alice Smith (USR-8492)", "SES-SYNAPSE-2026", alice_sig, "stress_demo", alice_chunks, request=request)
    _persist_watermark("Bob Jones (USR-3104)", "SES-SYNAPSE-2026", bob_sig, "stress_demo", bob_chunks, request=request)

    return {
        "status": "success",
        "alice": {
            "recipient_id": "Alice Smith (USR-8492)",
            "session_id": "SES-SYNAPSE-2026",
            "signature": alice_sig,
            "chunks_embedded": alice_chunks,
            "watermarked_text": alice_doc,
        },
        "bob": {
            "recipient_id": "Bob Jones (USR-3104)",
            "session_id": "SES-SYNAPSE-2026",
            "signature": bob_sig,
            "chunks_embedded": bob_chunks,
            "watermarked_text": bob_doc,
        },
    }


class GoogleAuthRequest(BaseModel):
    token: str


class FirebaseAuthRequest(BaseModel):
    id_token: str


class SupabaseAuthRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


def create_jwt_token(email: str, name: str, picture: str = "") -> str:
    """Generates an application session token valid for 24 hours."""
    payload = {
        "sub": email,
        "name": name,
        "picture": picture,
        "exp": time.time() + (24 * 3600),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)


@app.post("/api/auth/google")
def google_auth_endpoint(req: GoogleAuthRequest, request: Request):
    """Verifies a Google ID token and returns a signed 24h application JWT session."""
    try:
        id_info = id_token.verify_oauth2_token(
            req.token,
            google_requests.Request(),
            audience=None,
        )
        token_aud = id_info.get("aud")
        if ALLOWED_GOOGLE_CLIENT_IDS and token_aud not in ALLOWED_GOOGLE_CLIENT_IDS:
            raise HTTPException(status_code=401, detail=f"Google token audience mismatch: {token_aud}")

        email = id_info.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid Google Token: Missing email.")

        name = id_info.get("name") or email.split("@")[0]
        picture = id_info.get("picture", "")

        session_token = create_jwt_token(email, name, picture)
        proto = _get_forwarded_proto(request)
        fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "leaklens-tyrn.vercel.app"

        return {
            "status": "success",
            "access_token": session_token,
            "resolved_origin": f"{proto}://{fwd_host}",
            "user": {
                "email": email,
                "name": name,
                "picture": picture,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Google authentication failed: {str(e)}")


@app.post("/api/auth/firebase")
def firebase_auth_endpoint(req: FirebaseAuthRequest, request: Request):
    """Verifies a Firebase Authentication ID token and returns a signed 24h application JWT session."""
    try:
        decoded = id_token.verify_firebase_token(
            req.id_token,
            google_requests.Request(),
            audience=FIREBASE_PROJECT_ID,
        )
        email = decoded.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid Firebase Token: Missing email.")

        name = decoded.get("name") or email.split("@")[0]
        picture = decoded.get("picture", "")
        firebase_uid = decoded.get("uid") or decoded.get("sub") or ""

        session_token = create_jwt_token(email, name, picture)
        proto = _get_forwarded_proto(request)
        fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "leaklens-tyrn.vercel.app"

        return {
            "status": "success",
            "provider": "firebase",
            "access_token": session_token,
            "firebase_uid": firebase_uid,
            "resolved_origin": f"{proto}://{fwd_host}",
            "user": {
                "email": email,
                "name": name,
                "picture": picture,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Firebase authentication failed: {str(e)}")


@app.post("/api/auth/supabase/signup")
def supabase_signup_endpoint(req: SupabaseAuthRequest):
    """Registers an operator account in Supabase Auth and returns a LeakLens session if confirmed."""
    status_code, data = supabase_store.sign_up_password(req.email.strip(), req.password, req.name or "")
    if status_code >= 400:
        msg = data.get("msg") or data.get("error_description") or data.get("message") or "Supabase sign-up failed."
        raise HTTPException(status_code=status_code, detail=msg)
    sb_access_token = data.get("access_token")
    user_obj = data.get("user") or {}
    email = user_obj.get("email") or req.email.strip()
    name = (user_obj.get("user_metadata") or {}).get("name") or req.name or email.split("@")[0]
    if sb_access_token:
        return {
            "status": "success",
            "confirmation_required": False,
            "access_token": create_jwt_token(email, name),
            "supabase_access_token": sb_access_token,
            "user": {"email": email, "name": name, "picture": ""},
        }
    return {
        "status": "pending_confirmation",
        "confirmation_required": True,
        "message": f"Verification email sent to {email}. Confirm your inbox then sign in.",
        "user": {"email": email, "name": name, "picture": ""},
    }


@app.post("/api/auth/supabase/signin")
def supabase_signin_endpoint(req: SupabaseAuthRequest):
    """Authenticates via Supabase Auth and returns LeakLens JWT + RLS-scoped Supabase access token."""
    status_code, data = supabase_store.sign_in_password(req.email.strip(), req.password)
    if status_code >= 400:
        msg = data.get("msg") or data.get("error_description") or data.get("message") or "Supabase sign-in failed."
        raise HTTPException(status_code=status_code, detail=msg)
    sb_access_token = data.get("access_token")
    user_obj = data.get("user") or {}
    email = user_obj.get("email") or req.email.strip()
    name = (user_obj.get("user_metadata") or {}).get("name") or email.split("@")[0]
    return {
        "status": "success",
        "access_token": create_jwt_token(email, name),
        "supabase_access_token": sb_access_token,
        "user": {"email": email, "name": name, "picture": ""},
    }


@app.get("/api/auth/me")
def get_current_user(authorization: str = Header(None)):
    """Validates active user session from Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header.")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "status": "authenticated",
            "user": {
                "email": payload["sub"],
                "name": payload["name"],
                "picture": payload.get("picture", ""),
            },
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.PyJWTError:
        try:
            fb_user = id_token.verify_firebase_token(
                token,
                google_requests.Request(),
                audience=FIREBASE_PROJECT_ID,
            )
            if fb_user and fb_user.get("email"):
                return {
                    "status": "authenticated",
                    "provider": "firebase",
                    "user": {
                        "email": fb_user["email"],
                        "name": fb_user.get("name") or fb_user["email"].split("@")[0],
                        "picture": fb_user.get("picture", ""),
                    },
                }
        except Exception:
            pass

        sb_user = supabase_store.verify_user_jwt(token)
        if sb_user and sb_user.get("email"):
            meta = sb_user.get("user_metadata") or {}
            return {
                "status": "authenticated",
                "provider": "supabase",
                "user": {
                    "email": sb_user["email"],
                    "name": meta.get("name") or sb_user["email"].split("@")[0],
                    "picture": meta.get("avatar_url", ""),
                },
            }
        raise HTTPException(status_code=401, detail="Invalid session token.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        app_dir=os.path.dirname(os.path.abspath(__file__)),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
