import json
import base64
import sqlite3
import secrets
import time
from typing import Optional, Dict, Any, Tuple

from flask import Flask, request, jsonify, session, Response

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AttestationConveyancePreference,
)

APP_PORT = 5000
RP_NAME = "Uhuru Bank Demo"
DB_PATH = "uhuru_bank.sqlite3"
MAX_PASSKEYS = 3

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


# -----------------------------
# Small helpers
# -----------------------------
def now_ts() -> int:
    return int(time.time())


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def host_and_origin() -> Tuple[str, str]:
    """
    Fixes your "NotAllowedError" problem:
    WebAuthn requires rp_id to match the current hostname.
    So we generate rp_id and expected_origin dynamically based on how you opened the site
    (localhost vs 127.0.0.1).
    """
    host = request.host.split(":")[0]  # hostname only
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    origin = f"{scheme}://{request.host}"
    return host, origin


# -----------------------------
# DB
# -----------------------------
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def ensure_column(con: sqlite3.Connection, table: str, col: str, col_type_sql: str) -> None:
    cur = con.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = {r["name"] for r in cur.fetchall()}
    if col not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type_sql}")
        con.commit()


def init_db() -> None:
    con = db()
    cur = con.cursor()

    # Core tables
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','user')),
        webauthn_user_id_b64 TEXT NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        user_id INTEGER PRIMARY KEY,
        balance INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id_b64 TEXT NOT NULL,
        public_key_b64 TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        device_type TEXT,
        backed_up INTEGER,
        transports_json TEXT,
        UNIQUE(user_id, credential_id_b64),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    # Challenges (store rp_id + origin used, to verify correctly)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('register','auth','tx')),
        challenge_b64 TEXT NOT NULL,
        rp_id TEXT,
        origin TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    # Pending transfers (step-up auth for each tx)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS pending_tx (
        session_token TEXT PRIMARY KEY,
        from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )""")

    # Transaction history
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tx (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK(kind IN ('deposit','transfer')),
        from_user_id INTEGER,
        to_user_id INTEGER,
        amount INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )""")

    con.commit()

    # Ensure new columns exist if you ran older versions
    ensure_column(con, "challenges", "rp_id", "TEXT")
    ensure_column(con, "challenges", "origin", "TEXT")

    # Seed demo users
    def ensure_user(username: str, role: str):
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if row:
            return row["id"]
        user_handle = b64url_encode(secrets.token_bytes(16))
        cur.execute(
            "INSERT INTO users(username, role, webauthn_user_id_b64) VALUES (?,?,?)",
            (username, role, user_handle),
        )
        uid = cur.lastrowid
        cur.execute("INSERT OR IGNORE INTO accounts(user_id, balance) VALUES (?,0)", (uid,))
        con.commit()
        return uid

    ensure_user("admin", "admin")
    ensure_user("user1", "user")
    ensure_user("user2", "user")

    con.close()


# -----------------------------
# DB queries
# -----------------------------
def get_user(username: str) -> Optional[sqlite3.Row]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def get_user_by_id(uid: int) -> Optional[sqlite3.Row]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    con.close()
    return row


def list_creds(user_id: int):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM credentials WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = cur.fetchall()
    con.close()
    return rows


def get_cred_by_id(user_id: int, cred_id_b64: str) -> Optional[sqlite3.Row]:
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT * FROM credentials WHERE user_id=? AND credential_id_b64=?",
        (user_id, cred_id_b64),
    )
    row = cur.fetchone()
    con.close()
    return row


def add_credential(user_id: int, verification) -> str:
    cred_id_b64 = b64url_encode(verification.credential_id)
    pub_key_b64 = b64url_encode(verification.credential_public_key)
    transports_json = json.dumps(getattr(verification, "transports", None))

    con = db()
    cur = con.cursor()
    cur.execute(
        """INSERT INTO credentials(user_id, credential_id_b64, public_key_b64, sign_count, created_at, device_type, backed_up, transports_json)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            user_id,
            cred_id_b64,
            pub_key_b64,
            int(verification.sign_count),
            now_ts(),
            getattr(verification, "credential_device_type", None),
            1 if getattr(verification, "credential_backed_up", False) else 0,
            transports_json,
        ),
    )
    con.commit()
    con.close()
    return cred_id_b64


def delete_credential(user_id: int, cred_id_b64: str) -> None:
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM credentials WHERE user_id=? AND credential_id_b64=?", (user_id, cred_id_b64))
    con.commit()
    con.close()


def update_cred_sign_count(user_id: int, cred_id_b64: str, new_sign_count: int, device_type: str, backed_up: bool):
    con = db()
    cur = con.cursor()
    cur.execute(
        "UPDATE credentials SET sign_count=?, device_type=?, backed_up=? WHERE user_id=? AND credential_id_b64=?",
        (new_sign_count, device_type, 1 if backed_up else 0, user_id, cred_id_b64),
    )
    con.commit()
    con.close()


def get_balance(user_id: int) -> int:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT balance FROM accounts WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    con.close()
    return int(row["balance"]) if row else 0


def set_balance(user_id: int, balance: int) -> None:
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE accounts SET balance=? WHERE user_id=?", (balance, user_id))
    con.commit()
    con.close()


def record_tx(kind: str, amount: int, from_user_id: Optional[int], to_user_id: Optional[int]) -> None:
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO tx(kind, from_user_id, to_user_id, amount, created_at) VALUES (?,?,?,?,?)",
        (kind, from_user_id, to_user_id, amount, now_ts()),
    )
    con.commit()
    con.close()


def list_tx_for_user(user_id: int, limit: int = 50):
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT t.*, fu.username AS from_username, tu.username AS to_username
        FROM tx t
        LEFT JOIN users fu ON fu.id = t.from_user_id
        LEFT JOIN users tu ON tu.id = t.to_user_id
        WHERE t.from_user_id = ? OR t.to_user_id = ?
        ORDER BY t.id DESC
        LIMIT ?
    """, (user_id, user_id, limit))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def list_tx_all(limit: int = 100):
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT t.*, fu.username AS from_username, tu.username AS to_username
        FROM tx t
        LEFT JOIN users fu ON fu.id = t.from_user_id
        LEFT JOIN users tu ON tu.id = t.to_user_id
        ORDER BY t.id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


# -----------------------------
# Challenge + session helpers
# -----------------------------
def session_token() -> str:
    if "sess_token" not in session:
        session["sess_token"] = secrets.token_urlsafe(24)
    return session["sess_token"]


def store_challenge(user_id: int, kind: str, challenge_b64: str, rp_id: str, origin: str) -> None:
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO challenges(user_id, kind, challenge_b64, rp_id, origin, created_at) VALUES (?,?,?,?,?,?)",
        (user_id, kind, challenge_b64, rp_id, origin, now_ts()),
    )
    con.commit()
    con.close()


def latest_challenge(user_id: int, kind: str, max_age_sec: int = 180) -> Optional[Dict[str, Any]]:
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT challenge_b64, rp_id, origin, created_at
        FROM challenges
        WHERE user_id=? AND kind=?
        ORDER BY id DESC
        LIMIT 1
    """, (user_id, kind))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    if now_ts() - int(row["created_at"]) > max_age_sec:
        return None
    return {
        "challenge_b64": row["challenge_b64"],
        "rp_id": row["rp_id"],
        "origin": row["origin"],
    }


def put_pending_tx(from_user_id: int, to_user_id: int, amount: int) -> None:
    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO pending_tx(session_token, from_user_id, to_user_id, amount, created_at)
        VALUES (?,?,?,?,?)
    """, (session_token(), from_user_id, to_user_id, amount, now_ts()))
    con.commit()
    con.close()


def pop_pending_tx() -> Optional[sqlite3.Row]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM pending_tx WHERE session_token=?", (session_token(),))
    row = cur.fetchone()
    cur.execute("DELETE FROM pending_tx WHERE session_token=?", (session_token(),))
    con.commit()
    con.close()
    return row


def require_login():
    if not session.get("authed") or not session.get("username"):
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    return None


def current_user() -> sqlite3.Row:
    u = get_user(session["username"])
    if not u:
        raise RuntimeError("Session user missing from DB")
    return u


# -----------------------------
# UI: Banking app SPA (light theme)
# -----------------------------
HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Uhuru Bank Demo</title>
  <style>
    :root{
      --bg:#f6f8fc;
      --card:#ffffff;
      --text:#0b1220;
      --muted:#5b677a;
      --line:#e6eaf2;
      --primary:#1d4ed8;
      --primary2:#2563eb;
      --good:#16a34a;
      --bad:#dc2626;
      --shadow: 0 10px 30px rgba(17, 24, 39, .10);
      --radius: 18px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New";
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(1200px 500px at 20% -10%, rgba(37,99,235,.18), transparent 60%),
                  radial-gradient(900px 450px at 80% 0%, rgba(29,78,216,.12), transparent 55%),
                  var(--bg);
      color:var(--text);
    }
    a{color:var(--primary); text-decoration:none}
    .wrap{max-width: 980px; margin: 0 auto; padding: 18px 16px 90px;}
    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      padding: 14px 14px;
      background: rgba(255,255,255,.70);
      backdrop-filter: blur(10px);
      border:1px solid var(--line);
      border-radius: 22px;
      box-shadow: var(--shadow);
      position: sticky; top: 12px; z-index: 10;
    }
    .brand{
      display:flex; gap:10px; align-items:center;
    }
    .logo{
      width:38px; height:38px; border-radius: 12px;
      background: linear-gradient(135deg, var(--primary), #60a5fa);
      box-shadow: 0 12px 25px rgba(29,78,216,.25);
    }
    .brand h1{font-size:16px; margin:0; line-height:1.1}
    .brand p{margin:0; font-size:12px; color:var(--muted)}
    .pill{
      font-size:12px; color:#0b1220;
      background:#eef2ff; border:1px solid #dbe3ff;
      padding: 7px 10px; border-radius: 999px;
      display:flex; align-items:center; gap:8px;
    }
    .dot{width:8px;height:8px;border-radius:999px;background:var(--good)}
    .grid{display:grid; gap:14px}
    .grid2{grid-template-columns: 1.1fr .9fr}
    @media (max-width: 860px){ .grid2{grid-template-columns: 1fr} }

    .card{
      background: rgba(255,255,255,.92);
      border:1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
    }
    .titleRow{display:flex; align-items:flex-end; justify-content:space-between; gap:10px}
    .title{
      margin:0; font-size:16px; letter-spacing: .2px;
    }
    .sub{margin: 6px 0 0; color:var(--muted); font-size:13px}

    .btn{
      border:1px solid var(--line);
      background: white;
      padding: 11px 12px;
      border-radius: 14px;
      cursor:pointer;
      font-weight: 650;
      color: var(--text);
      display:inline-flex; align-items:center; justify-content:center; gap:10px;
      transition: transform .05s ease, background .15s ease, border .15s ease;
    }
    .btn:active{transform: scale(.985)}
    .btn:hover{background:#f9fbff; border-color:#dae2f2}
    .btnPrimary{
      background: linear-gradient(180deg, var(--primary2), var(--primary));
      border-color: rgba(29,78,216,.35);
      color:white;
    }
    .btnPrimary:hover{filter: brightness(1.03)}
    .btnDanger{background:#fff1f2;border-color:#ffe4e6;color:#9f1239}
    .btnGhost{background:transparent}
    .row{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .field{
      display:flex; flex-direction:column; gap:7px;
      min-width: 220px;
    }
    label{font-size:12px; color:var(--muted)}
    select, input{
      padding: 12px 12px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: white;
      outline:none;
      font-size: 14px;
    }
    select:focus, input:focus{border-color:#c7d2fe; box-shadow: 0 0 0 4px rgba(29,78,216,.12)}
    .kpi{
      display:flex; align-items:center; justify-content:space-between;
      padding: 14px;
      border-radius: 16px;
      border:1px solid var(--line);
      background: linear-gradient(180deg, #ffffff, #f8fbff);
    }
    .kpi .big{font-size:26px; font-weight:850; letter-spacing:-.5px}
    .kpi .small{font-size:12px; color:var(--muted)}
    .hint{
      font-size: 12px; color: var(--muted); line-height: 1.35;
      background: #f8fafc; border:1px dashed #e2e8f0;
      padding: 10px; border-radius: 14px;
    }
    .toast{
      font-family: var(--mono);
      font-size: 12px;
      white-space: pre-wrap;
      background: #0b1220;
      color: #e6edf7;
      border-radius: 14px;
      padding: 12px;
      border: 1px solid rgba(255,255,255,.08);
      margin-top: 10px;
      max-height: 220px;
      overflow: auto;
    }
    .table{
      width:100%;
      border-collapse: separate;
      border-spacing: 0;
      overflow:hidden;
      border-radius: 16px;
      border:1px solid var(--line);
      background: white;
    }
    .table th, .table td{
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      font-size: 13px;
      text-align:left;
    }
    .table th{color:var(--muted); font-weight: 750; font-size: 12px; background:#fbfcff}
    .tag{
      display:inline-flex; align-items:center; gap:6px;
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--line);
      background:#f8fbff;
    }
    .tag.good{border-color:#bbf7d0;background:#f0fdf4;color:#166534}
    .tag.bad{border-color:#fecaca;background:#fef2f2;color:#7f1d1d}
    .nav{
      position: fixed;
      left: 0; right: 0; bottom: 0;
      background: rgba(255,255,255,.88);
      backdrop-filter: blur(10px);
      border-top: 1px solid var(--line);
      padding: 10px 12px;
    }
    .navInner{
      max-width: 980px; margin: 0 auto;
      display:flex; gap:8px; justify-content:space-between;
    }
    .nav a{
      flex:1;
      display:flex; flex-direction:column; align-items:center; justify-content:center;
      padding: 10px 6px;
      border-radius: 14px;
      color: var(--muted);
      font-size: 11px;
      border: 1px solid transparent;
    }
    .nav a.active{
      background:#eef2ff;
      color: var(--primary);
      border-color:#dbe3ff;
      font-weight: 800;
    }
    .nav svg{width:18px;height:18px}
    .split{height:1px;background:var(--line);margin:12px 0}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Uhuru Bank</h1>
          <p>Demo • Fingerprint approvals via Windows Hello</p>
        </div>
      </div>
      <div class="pill"><span class="dot" id="dot"></span><span id="who">Not logged in</span></div>
    </div>

    <div id="view" style="margin-top:14px;"></div>
  </div>

  <div class="nav">
    <div class="navInner" id="navInner">
      <!-- filled by JS -->
    </div>
  </div>

<script>
  // --- Mini router (hash pages) ---
  const routes = ["login","dashboard","transfer","deposit","history","settings"];
  function page(){ return (location.hash || "#/login").replace("#/",""); }
  function go(p){ location.hash = "#/" + p; render(); }

  function icon(name){
    const icons = {
      login: `<svg viewBox="0 0 24 24" fill="none"><path d="M10 8V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-7a2 2 0 0 1-2-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M15 12H3m0 0 3-3m-3 3 3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
      dashboard:`<svg viewBox="0 0 24 24" fill="none"><path d="M4 13h6V4H4v9Zm10 7h6V11h-6v9ZM4 20h6v-5H4v5Zm10-11h6V4h-6v5Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>`,
      transfer:`<svg viewBox="0 0 24 24" fill="none"><path d="M7 7h11l-2-2m2 2-2 2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M17 17H6l2 2m-2-2 2-2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
      deposit:`<svg viewBox="0 0 24 24" fill="none"><path d="M12 3v18m0-18 4 4m-4-4-4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 13v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
      history:`<svg viewBox="0 0 24 24" fill="none"><path d="M3 3v6h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M3.5 13a9 9 0 1 0 2.2-6.1L3 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 7v6l4 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
      settings:`<svg viewBox="0 0 24 24" fill="none"><path d="M12 15.5A3.5 3.5 0 1 0 12 8.5a3.5 3.5 0 0 0 0 7Z" stroke="currentColor" stroke-width="2"/><path d="M19.4 15a7.8 7.8 0 0 0 .1-2l2-1.2-2-3.4-2.3.6a7.5 7.5 0 0 0-1.7-1L15.1 5h-4l-.4 2.9a7.5 7.5 0 0 0-1.7 1L6.7 8.4l-2 3.4 2 1.2a7.8 7.8 0 0 0 .1 2l-2 1.2 2 3.4 2.3-.6a7.5 7.5 0 0 0 1.7 1l.4 2.9h4l.4-2.9a7.5 7.5 0 0 0 1.7-1l2.3.6 2-3.4-2-1.2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>`
    };
    return icons[name] || "";
  }

  // --- API wrapper ---
  async function api(path, method="GET", body=null){
    const opts = { method, headers: { "Content-Type":"application/json" } };
    if(body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    const data = await r.json().catch(()=>({ok:false,error:"Bad JSON"}));
    if(!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }

  // --- WebAuthn helpers ---
  function b64urlToBuf(b64url){
    const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g,'+').replace(/_/g,'/');
    const str = atob(b64);
    const bytes = new Uint8Array(str.length);
    for(let i=0;i<str.length;i++) bytes[i]=str.charCodeAt(i);
    return bytes.buffer;
  }
  function bufToB64url(buf){
    const bytes = new Uint8Array(buf);
    let str='';
    for(const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  }
  function credentialToJSON(cred){
    if(!cred) return null;
    const res = { id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type };
    if(cred.response){
      const r = cred.response;
      res.response = {};
      if(r.clientDataJSON) res.response.clientDataJSON = bufToB64url(r.clientDataJSON);
      if(r.attestationObject) res.response.attestationObject = bufToB64url(r.attestationObject);
      if(r.authenticatorData) res.response.authenticatorData = bufToB64url(r.authenticatorData);
      if(r.signature) res.response.signature = bufToB64url(r.signature);
      if(r.userHandle) res.response.userHandle = bufToB64url(r.userHandle);
      if(r.transports && typeof r.transports === 'function') res.response.transports = r.transports();
    }
    return res;
  }

  function friendlyWebauthnError(e){
    const msg = (e && (e.message || String(e))) || "Unknown error";
    // Browser throws NotAllowedError when RP/origin mismatch, user cancels, or timeout.
    if(String(msg).toLowerCase().includes("not allowed") || String(msg).toLowerCase().includes("timed out")){
      return `NotAllowed/Timeout.\n\nCommon fixes:\n• Make sure you opened the app in the SAME address the server sees (e.g. use http://localhost:5000 OR http://127.0.0.1:5000, but be consistent).\n• Use Chrome or Edge.\n• Ensure Windows Hello fingerprint is set up.\n• When the Windows Hello prompt appears, complete it (don’t click away).\n\nRaw: ${msg}`;
    }
    return msg;
  }

  // --- App state ---
  let state = { me:null, balances:null, tx:[], keys:[], status:null, toast:"" };

  function toast(txt){ state.toast = txt; render(); }
  function clearToast(){ state.toast = ""; render(); }

  async function refreshStatus(){
    const s = await api("/api/status");
    state.status = s;
    state.me = s.user;
    // top pill
    const who = document.getElementById("who");
    const dot = document.getElementById("dot");
    if(s.user){
      who.textContent = `${s.user.username} • ${s.user.role}`;
      dot.style.background = "#16a34a";
    } else {
      who.textContent = "Not logged in";
      dot.style.background = "#ef4444";
    }
  }

  async function loadDashboard(){
    const d = await api("/api/dashboard");
    state.balances = d;
    state.tx = d.recent_tx || [];
  }

  async function loadTx(){
    const d = await api("/api/tx");
    state.tx = d.tx || [];
  }

  async function loadKeys(){
    const d = await api("/api/credentials");
    state.keys = d.passkeys || [];
  }

  async function registerPasskey(username){
    try{
      toast("Starting passkey registration…");
      const r = await api("/api/webauthn/register/options", "POST", { username });
      const opts = r.publicKey;
      opts.challenge = b64urlToBuf(opts.challenge);
      opts.user.id = b64urlToBuf(opts.user.id);
      if(opts.excludeCredentials){
        for(const c of opts.excludeCredentials) c.id = b64urlToBuf(c.id);
      }
      const cred = await navigator.credentials.create({ publicKey: opts });
      const payload = credentialToJSON(cred);
      const out = await api("/api/webauthn/register/verify", "POST", { username, credential: payload });
      toast(JSON.stringify(out, null, 2));
      await refreshStatus();
      if(page() !== "login") await loadKeys();
    }catch(e){
      toast(friendlyWebauthnError(e));
    }
  }

  async function login(username){
    try{
      toast("Requesting fingerprint…");
      const r = await api("/api/webauthn/auth/options", "POST", { username });
      const opts = r.publicKey;
      opts.challenge = b64urlToBuf(opts.challenge);
      if(opts.allowCredentials){
        for(const c of opts.allowCredentials) c.id = b64urlToBuf(c.id);
      }
      const assertion = await navigator.credentials.get({ publicKey: opts });
      const payload = credentialToJSON(assertion);
      const out = await api("/api/webauthn/auth/verify", "POST", { username, credential: payload });
      toast(JSON.stringify(out, null, 2));
      await refreshStatus();
      go("dashboard");
    }catch(e){
      toast(friendlyWebauthnError(e));
    }
  }

  async function logout(){
    await api("/api/logout","POST",{});
    await refreshStatus();
    state.balances = null; state.tx = []; state.keys = [];
    go("login");
  }

  async function doDeposit(to_username, amount){
    try{
      toast("Processing deposit…");
      const out = await api("/api/admin/deposit","POST",{ to_username, amount: Number(amount) });
      toast(JSON.stringify(out, null, 2));
      await loadDashboard();
    }catch(e){
      toast(String(e.message || e));
    }
  }

  async function doTransfer(to_username, amount){
    try{
      toast("Preparing transfer authorization (fingerprint)…");
      const r = await api("/api/transfer/options","POST",{ to_username, amount: Number(amount) });
      const opts = r.publicKey;
      opts.challenge = b64urlToBuf(opts.challenge);
      if(opts.allowCredentials){
        for(const c of opts.allowCredentials) c.id = b64urlToBuf(c.id);
      }
      const assertion = await navigator.credentials.get({ publicKey: opts });
      const payload = credentialToJSON(assertion);
      const out = await api("/api/transfer/verify","POST",{ credential: payload });
      toast(JSON.stringify(out, null, 2));
      await loadDashboard();
    }catch(e){
      toast(friendlyWebauthnError(e));
    }
  }

  async function deleteKey(cred_id_b64){
    try{
      const out = await api("/api/credentials/delete","POST",{ cred_id_b64 });
      toast(JSON.stringify(out, null, 2));
      await loadKeys();
    }catch(e){
      toast(String(e.message || e));
    }
  }

  // --- Views ---
  function viewLogin(){
    const s = state.status || {};
    return `
      <div class="grid grid2">
        <div class="card">
          <div class="titleRow">
            <h2 class="title">Sign in</h2>
            <span class="tag good">Demo</span>
          </div>
          <p class="sub">Choose an account and use your fingerprint (Windows Hello).</p>

          <div class="split"></div>

          <div class="row">
            <div class="field">
              <label>Demo account</label>
              <select id="login_user">
                <option value="user1">user1</option>
                <option value="user2">user2</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>

          <div class="row" style="margin-top:10px;">
            <button class="btn btnPrimary" onclick="(async()=>{ const u=document.getElementById('login_user').value; await login(u); })()">
              ${icon("login")} Login with fingerprint
            </button>
            <button class="btn" onclick="(async()=>{ const u=document.getElementById('login_user').value; await registerPasskey(u); })()">
              Register passkey
            </button>
          </div>

          <div class="hint" style="margin-top:12px;">
            <b>About fingers:</b> This app does not “choose” index/middle finger. Windows Hello does.
            To use other fingers: Windows Settings → Accounts → Sign-in options → Fingerprint → Add another.
            <br/><br/>
            <b>If you see “NotAllowed/Timeout”:</b> open the app consistently as <span style="font-family:var(--mono)">http://localhost:5000</span> or
            <span style="font-family:var(--mono)">http://127.0.0.1:5000</span>, use Edge/Chrome, and complete the Windows Hello prompt.
          </div>
        </div>

        <div class="card">
          <h2 class="title">Connection details</h2>
          <p class="sub">These must match for WebAuthn to work.</p>
          <div class="split"></div>
          <div class="kpi">
            <div>
              <div class="small">Current Origin</div>
              <div style="font-family:var(--mono); font-size:13px">${location.origin}</div>
            </div>
          </div>
          <div style="height:10px"></div>
          <div class="kpi">
            <div>
              <div class="small">Server sees RP ID</div>
              <div style="font-family:var(--mono); font-size:13px">${(s.rp_id||"(load status)")}</div>
            </div>
          </div>
          <div style="height:10px"></div>
          <button class="btn" onclick="refreshAll()">Refresh status</button>
        </div>
      </div>
      ${toastBlock()}
    `;
  }

  function viewDashboard(){
    const d = state.balances;
    if(!d) return `<div class="card"><p class="sub">Loading…</p></div>`;
    const me = d.me;
    const bal = d.me_balance ?? 0;
    const recent = (d.recent_tx||[]).slice(0,6);

    return `
      <div class="grid grid2">
        <div class="card">
          <div class="titleRow">
            <h2 class="title">Home</h2>
            <button class="btn btnGhost" onclick="refreshAll()">Refresh</button>
          </div>
          <p class="sub">Welcome back, <b>${me.username}</b>.</p>

          <div class="split"></div>

          <div class="kpi">
            <div>
              <div class="small">Available balance</div>
              <div class="big">KES ${bal.toLocaleString()}</div>
              <div class="small">Demo currency (virtual)</div>
            </div>
            <div class="row">
              <button class="btn btnPrimary" onclick="go('transfer')">${icon("transfer")} Transfer</button>
              ${me.role==="admin" ? `<button class="btn" onclick="go('deposit')">${icon("deposit")} Deposit</button>` : ``}
            </div>
          </div>

          <div class="split"></div>

          <div class="row">
            <button class="btn" onclick="go('history')">${icon("history")} History</button>
            <button class="btn" onclick="go('settings')">${icon("settings")} Settings</button>
            <button class="btn btnDanger" onclick="logout()">Logout</button>
          </div>
        </div>

        <div class="card">
          <div class="titleRow">
            <h2 class="title">Recent activity</h2>
            <span class="tag">${me.role==="admin" ? "All users" : "Your account"}</span>
          </div>
          <p class="sub">Latest transactions.</p>
          <div class="split"></div>
          ${txTable(recent)}
        </div>
      </div>
      ${toastBlock()}
    `;
  }

  function viewTransfer(){
    return `
      <div class="card">
        <div class="titleRow">
          <h2 class="title">Transfer</h2>
          <button class="btn btnGhost" onclick="go('dashboard')">Back</button>
        </div>
        <p class="sub">Every transfer requires a fresh fingerprint prompt.</p>
        <div class="split"></div>

        <div class="row">
          <div class="field">
            <label>Send to</label>
            <select id="tx_to">
              <option value="user2">user2</option>
              <option value="user1">user1</option>
            </select>
          </div>
          <div class="field">
            <label>Amount (KES)</label>
            <input id="tx_amount" type="number" value="200" min="1"/>
          </div>
        </div>

        <div class="row" style="margin-top:12px;">
          <button class="btn btnPrimary" onclick="(async()=>{ 
            const to=document.getElementById('tx_to').value; 
            const amt=document.getElementById('tx_amount').value; 
            await doTransfer(to, amt); 
          })()">
            ${icon("transfer")} Authorize & Send (Fingerprint)
          </button>
          <button class="btn" onclick="clearToast()">Clear message</button>
        </div>

        <div class="hint" style="margin-top:12px;">
          If you want “middle finger / thumb” instead of index: add that finger in Windows Hello.
          The app will accept whichever enrolled finger you present.
        </div>
      </div>
      ${toastBlock()}
    `;
  }

  function viewDeposit(){
    const me = state.me;
    if(!me || me.role!=="admin"){
      return `
        <div class="card">
          <h2 class="title">Deposit</h2>
          <p class="sub">Admin only.</p>
          <div class="split"></div>
          <button class="btn" onclick="go('dashboard')">Back</button>
        </div>
        ${toastBlock()}
      `;
    }

    return `
      <div class="card">
        <div class="titleRow">
          <h2 class="title">Admin Deposit</h2>
          <button class="btn btnGhost" onclick="go('dashboard')">Back</button>
        </div>
        <p class="sub">Demo-only: admin credits balances directly.</p>
        <div class="split"></div>

        <div class="row">
          <div class="field">
            <label>Credit user</label>
            <select id="dep_to">
              <option value="user1">user1</option>
              <option value="user2">user2</option>
            </select>
          </div>
          <div class="field">
            <label>Amount (KES)</label>
            <input id="dep_amount" type="number" value="1000" min="1"/>
          </div>
        </div>

        <div class="row" style="margin-top:12px;">
          <button class="btn btnPrimary" onclick="(async()=>{ 
            const to=document.getElementById('dep_to').value; 
            const amt=document.getElementById('dep_amount').value; 
            await doDeposit(to, amt);
          })()">${icon("deposit")} Deposit</button>
          <button class="btn" onclick="clearToast()">Clear message</button>
        </div>
      </div>
      ${toastBlock()}
    `;
  }

  function viewHistory(){
    return `
      <div class="card">
        <div class="titleRow">
          <h2 class="title">Transaction history</h2>
          <button class="btn btnGhost" onclick="go('dashboard')">Back</button>
        </div>
        <p class="sub">Full list (latest first).</p>
        <div class="split"></div>
        ${txTable(state.tx || [])}
        <div class="row" style="margin-top:12px;">
          <button class="btn" onclick="(async()=>{ await loadTx(); render(); })()">Refresh</button>
        </div>
      </div>
      ${toastBlock()}
    `;
  }

  function viewSettings(){
    const me = state.me;
    const keys = state.keys || [];
    return `
      <div class="card">
        <div class="titleRow">
          <h2 class="title">Settings</h2>
          <button class="btn btnGhost" onclick="go('dashboard')">Back</button>
        </div>
        <p class="sub">Manage passkeys (max ${MAX_PASSKEYS}).</p>
        <div class="split"></div>

        <div class="row">
          <button class="btn btnPrimary" onclick="(async()=>{ await registerPasskey('${me?me.username:"user1"}'); })()">
            ${icon("settings")} Add passkey
          </button>
          <button class="btn" onclick="(async()=>{ await loadKeys(); render(); })()">Refresh list</button>
        </div>

        <div class="hint" style="margin-top:12px;">
          <b>Important:</b> This app stores <i>passkey credentials</i> (public key + id), not fingerprints.
          Your fingerprints stay inside Windows Hello. “3 fingerprints” here means “up to 3 passkeys”.
        </div>

        <div class="split"></div>

        <table class="table">
          <thead>
            <tr><th>Credential ID</th><th>Created</th><th>Sign count</th><th>Action</th></tr>
          </thead>
          <tbody>
            ${keys.length ? keys.map(k => `
              <tr>
                <td style="font-family:var(--mono); font-size:12px; max-width:420px; overflow:hidden; text-overflow:ellipsis;">${k.credential_id_b64}</td>
                <td>${new Date(k.created_at*1000).toLocaleString()}</td>
                <td>${k.sign_count}</td>
                <td><button class="btn btnDanger" onclick="deleteKey('${k.credential_id_b64}')">Delete</button></td>
              </tr>
            `).join("") : `<tr><td colspan="4" class="sub">No passkeys yet. Click “Add passkey”.</td></tr>`}
          </tbody>
        </table>
      </div>
      ${toastBlock()}
    `;
  }

  function txTable(items){
    if(!items || !items.length){
      return `<div class="hint">No transactions yet.</div>`;
    }
    return `
      <table class="table">
        <thead>
          <tr>
            <th>When</th>
            <th>Type</th>
            <th>From</th>
            <th>To</th>
            <th>Amount</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(t=>{
            const when = new Date(t.created_at*1000).toLocaleString();
            const kind = t.kind === "deposit" ? `<span class="tag good">deposit</span>` : `<span class="tag">transfer</span>`;
            const from = t.from_username || "-";
            const to = t.to_username || "-";
            const amt = `KES ${Number(t.amount).toLocaleString()}`;
            return `<tr><td>${when}</td><td>${kind}</td><td>${from}</td><td>${to}</td><td><b>${amt}</b></td></tr>`;
          }).join("")}
        </tbody>
      </table>
    `;
  }

  function toastBlock(){
    if(!state.toast) return "";
    return `
      <div class="card" style="margin-top:14px;">
        <div class="titleRow">
          <h2 class="title">Message</h2>
          <button class="btn btnGhost" onclick="clearToast()">Clear</button>
        </div>
        <div class="toast">${escapeHtml(state.toast)}</div>
      </div>
    `;
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
  }

  function renderNav(){
    const p = page();
    const me = state.me;
    const items = [
      {k:"login", label:"Login"},
      {k:"dashboard", label:"Home"},
      {k:"transfer", label:"Transfer"},
      {k:"deposit", label:"Deposit"},
      {k:"history", label:"History"},
      {k:"settings", label:"Settings"},
    ].filter(x => {
      if(x.k==="deposit") return me && me.role==="admin";
      return true;
    });

    const nav = document.getElementById("navInner");
    nav.innerHTML = items.map(it => `
      <a href="#/${it.k}" class="${p===it.k?'active':''}" onclick="render()">
        ${icon(it.k)}
        <div>${it.label}</div>
      </a>
    `).join("");
  }

  async function refreshAll(){
    try{
      await refreshStatus();
      if(state.me){
        await loadDashboard();
        await loadTx();
        await loadKeys();
      }
      render();
    }catch(e){
      toast(String(e.message || e));
    }
  }

  async function render(){
    const p = page();
    await refreshStatus();

    // guard: if not logged in, only login page
    if(!state.me && p !== "login"){
      location.hash = "#/login";
      return render();
    }

    // load data for pages
    if(state.me){
      if(p==="dashboard" && !state.balances) await loadDashboard();
      if(p==="history" && (!state.tx || !state.tx.length)) await loadTx();
      if(p==="settings" && (!state.keys || !state.keys.length)) await loadKeys();
    }

    renderNav();

    const view = document.getElementById("view");
    if(p==="login") view.innerHTML = viewLogin();
    else if(p==="dashboard") view.innerHTML = viewDashboard();
    else if(p==="transfer") view.innerHTML = viewTransfer();
    else if(p==="deposit") view.innerHTML = viewDeposit();
    else if(p==="history") view.innerHTML = viewHistory();
    else if(p==="settings") view.innerHTML = viewSettings();
    else view.innerHTML = viewLogin();
  }

  window.addEventListener("hashchange", render);

  // first load
  refreshAll().then(()=>render());
</script>
</body>
</html>
"""


# -----------------------------
# Routes: UI
# -----------------------------
@app.get("/")
def index():
    return Response(HTML, mimetype="text/html")


# -----------------------------
# API: status/auth
# -----------------------------
@app.get("/api/status")
def api_status():
    rp_id, origin = host_and_origin()
    user = None
    if session.get("authed") and session.get("username"):
        u = get_user(session["username"])
        if u:
            user = {"id": u["id"], "username": u["username"], "role": u["role"]}
    return jsonify({"ok": True, "user": user, "rp_id": rp_id, "origin": origin})


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


# -----------------------------
# WebAuthn: Registration
# -----------------------------
@app.post("/api/webauthn/register/options")
def register_options():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    u = get_user(username)
    if not u:
        return jsonify({"ok": False, "error": "Unknown user"}), 400

    rp_id, origin = host_and_origin()

    creds = list_creds(u["id"])
    if len(creds) >= MAX_PASSKEYS:
        return jsonify({"ok": False, "error": f"Max {MAX_PASSKEYS} passkeys reached. Delete one in Settings."}), 400

    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    selection = AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.PREFERRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=base64url_to_bytes(u["webauthn_user_id_b64"]),
        user_name=u["username"],
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=selection,
        exclude_credentials=exclude,
        timeout=60000,
    )

    opts_json = json.loads(options_to_json(opts))
    store_challenge(u["id"], "register", opts_json["challenge"], rp_id, origin)
    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/webauthn/register/verify")
def register_verify():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    credential = body.get("credential")
    u = get_user(username)
    if not u or not credential:
        return jsonify({"ok": False, "error": "Bad request"}), 400

    if len(list_creds(u["id"])) >= MAX_PASSKEYS:
        return jsonify({"ok": False, "error": f"Max {MAX_PASSKEYS} passkeys reached. Delete one in Settings."}), 400

    ch = latest_challenge(u["id"], "register")
    if not ch:
        return jsonify({"ok": False, "error": "Registration challenge expired. Try again."}), 400

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(ch["challenge_b64"]),
            expected_rp_id=ch["rp_id"],
            expected_origin=ch["origin"],
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Registration failed: {e}"}), 400

    cred_id = add_credential(u["id"], verification)
    return jsonify({"ok": True, "message": "Passkey registered.", "credential_id_b64": cred_id, "total": len(list_creds(u["id"]))})


# -----------------------------
# WebAuthn: Authentication (Login)
# -----------------------------
@app.post("/api/webauthn/auth/options")
def auth_options():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    u = get_user(username)
    if not u:
        return jsonify({"ok": False, "error": "Unknown user"}), 400

    rp_id, origin = host_and_origin()

    creds = list_creds(u["id"])
    if not creds:
        return jsonify({"ok": False, "error": "No passkeys registered. Click Register passkey first."}), 400

    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    opts_json = json.loads(options_to_json(opts))
    store_challenge(u["id"], "auth", opts_json["challenge"], rp_id, origin)
    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/webauthn/auth/verify")
def auth_verify():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    credential = body.get("credential")
    u = get_user(username)
    if not u or not credential:
        return jsonify({"ok": False, "error": "Bad request"}), 400

    ch = latest_challenge(u["id"], "auth")
    if not ch:
        return jsonify({"ok": False, "error": "Login challenge expired. Try again."}), 400

    cred_id_b64 = credential.get("id")
    if not cred_id_b64:
        return jsonify({"ok": False, "error": "Missing credential id"}), 400

    cred_row = get_cred_by_id(u["id"], cred_id_b64)
    if not cred_row:
        return jsonify({"ok": False, "error": "Unknown credential for this user"}), 400

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(ch["challenge_b64"]),
            expected_rp_id=ch["rp_id"],
            expected_origin=ch["origin"],
            credential_public_key=base64url_to_bytes(cred_row["public_key_b64"]),
            credential_current_sign_count=int(cred_row["sign_count"]),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Login failed: {e}"}), 400

    update_cred_sign_count(
        u["id"], cred_id_b64, int(verification.new_sign_count),
        getattr(verification, "credential_device_type", None),
        bool(getattr(verification, "credential_backed_up", False)),
    )

    session["username"] = username
    session["authed"] = True
    return jsonify({"ok": True, "message": f"Logged in as {username}"})


# -----------------------------
# Banking API
# -----------------------------
@app.get("/api/dashboard")
def api_dashboard():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    me_balance = get_balance(me["id"])

    # Admin sees all balances; user sees only theirs
    balances = []
    if me["role"] == "admin":
        con = db()
        cur = con.cursor()
        cur.execute("""
          SELECT u.username, u.role, a.balance
          FROM users u JOIN accounts a ON a.user_id=u.id
          ORDER BY u.username
        """)
        balances = [dict(r) for r in cur.fetchall()]
        con.close()

    # Recent transactions
    if me["role"] == "admin":
        recent = list_tx_all(20)
    else:
        recent = list_tx_for_user(me["id"], 20)

    return jsonify({
        "ok": True,
        "me": {"id": me["id"], "username": me["username"], "role": me["role"]},
        "me_balance": me_balance,
        "balances": balances,
        "recent_tx": recent,
    })


@app.post("/api/admin/deposit")
def api_deposit():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    if me["role"] != "admin":
        return jsonify({"ok": False, "error": "Admin only"}), 403

    body = request.get_json(force=True)
    to_username = (body.get("to_username") or "").strip()
    amount = int(body.get("amount") or 0)
    if amount <= 0:
        return jsonify({"ok": False, "error": "Amount must be > 0"}), 400

    to = get_user(to_username)
    if not to or to["role"] != "user":
        return jsonify({"ok": False, "error": "Deposit target must be user1/user2"}), 400

    set_balance(to["id"], get_balance(to["id"]) + amount)
    record_tx("deposit", amount, None, to["id"])

    return jsonify({"ok": True, "message": f"Deposited KES {amount} to {to_username}", "new_balance": get_balance(to["id"])})


@app.post("/api/transfer/options")
def api_transfer_options():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    if me["role"] != "user":
        return jsonify({"ok": False, "error": "Only user accounts can transfer in this demo"}), 403

    body = request.get_json(force=True)
    to_username = (body.get("to_username") or "").strip()
    amount = int(body.get("amount") or 0)
    if amount <= 0:
        return jsonify({"ok": False, "error": "Amount must be > 0"}), 400

    to = get_user(to_username)
    if not to or to["role"] != "user":
        return jsonify({"ok": False, "error": "Transfer target must be user1/user2"}), 400
    if to["id"] == me["id"]:
        return jsonify({"ok": False, "error": "Cannot transfer to yourself"}), 400

    # Save the intent, then require fingerprint assertion
    put_pending_tx(me["id"], to["id"], amount)

    rp_id, origin = host_and_origin()

    creds = list_creds(me["id"])
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    opts_json = json.loads(options_to_json(opts))
    store_challenge(me["id"], "tx", opts_json["challenge"], rp_id, origin)

    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/transfer/verify")
def api_transfer_verify():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    if me["role"] != "user":
        return jsonify({"ok": False, "error": "Only user accounts can transfer in this demo"}), 403

    body = request.get_json(force=True)
    credential = body.get("credential")
    if not credential:
        return jsonify({"ok": False, "error": "Missing credential"}), 400

    pending = pop_pending_tx()
    if not pending:
        return jsonify({"ok": False, "error": "No pending transfer found. Start again."}), 400

    ch = latest_challenge(me["id"], "tx")
    if not ch:
        return jsonify({"ok": False, "error": "Transfer challenge expired. Try again."}), 400

    cred_id_b64 = credential.get("id")
    if not cred_id_b64:
        return jsonify({"ok": False, "error": "Missing credential id"}), 400

    cred_row = get_cred_by_id(me["id"], cred_id_b64)
    if not cred_row:
        return jsonify({"ok": False, "error": "Unknown credential for this user"}), 400

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(ch["challenge_b64"]),
            expected_rp_id=ch["rp_id"],
            expected_origin=ch["origin"],
            credential_public_key=base64url_to_bytes(cred_row["public_key_b64"]),
            credential_current_sign_count=int(cred_row["sign_count"]),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Fingerprint verification failed: {e}"}), 400

    update_cred_sign_count(
        me["id"], cred_id_b64, int(verification.new_sign_count),
        getattr(verification, "credential_device_type", None),
        bool(getattr(verification, "credential_backed_up", False)),
    )

    amount = int(pending["amount"])
    from_id = int(pending["from_user_id"])
    to_id = int(pending["to_user_id"])

    # Funds move (simple demo)
    if get_balance(from_id) < amount:
        return jsonify({"ok": False, "error": "Insufficient funds"}), 400

    set_balance(from_id, get_balance(from_id) - amount)
    set_balance(to_id, get_balance(to_id) + amount)
    record_tx("transfer", amount, from_id, to_id)

    to_user = get_user_by_id(to_id)
    return jsonify({
        "ok": True,
        "message": f"Transfer successful: KES {amount} to {to_user['username'] if to_user else 'recipient'}",
        "your_new_balance": get_balance(me["id"]),
    })


@app.get("/api/tx")
def api_tx():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    if me["role"] == "admin":
        tx = list_tx_all(100)
    else:
        tx = list_tx_for_user(me["id"], 100)

    return jsonify({"ok": True, "tx": tx})


@app.get("/api/credentials")
def api_credentials():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    rows = list_creds(me["id"])
    out = []
    for r in rows:
        out.append({
            "credential_id_b64": r["credential_id_b64"],
            "sign_count": int(r["sign_count"]),
            "created_at": int(r["created_at"]),
            "device_type": r["device_type"],
            "backed_up": bool(r["backed_up"]) if r["backed_up"] is not None else None,
        })
    return jsonify({"ok": True, "username": me["username"], "count": len(out), "passkeys": out})


@app.post("/api/credentials/delete")
def api_credentials_delete():
    maybe = require_login()
    if maybe:
        return maybe

    me = current_user()
    body = request.get_json(force=True)
    cred_id_b64 = (body.get("cred_id_b64") or "").strip()
    if not cred_id_b64:
        return jsonify({"ok": False, "error": "Missing cred_id_b64"}), 400

    if not get_cred_by_id(me["id"], cred_id_b64):
        return jsonify({"ok": False, "error": "Credential not found for this user"}), 404

    delete_credential(me["id"], cred_id_b64)
    return jsonify({"ok": True, "message": "Deleted", "remaining": len(list_creds(me["id"]))})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=APP_PORT, debug=True)
