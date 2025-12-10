import json
import base64
import sqlite3
import secrets
import time
from typing import Optional

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
RP_ID = "localhost"            # domain only, no port
RP_NAME = "Fingerprint Bank Demo"
DB_PATH = "bank_demo.sqlite3"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


# -----------------------------
# Helpers
# -----------------------------
def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def now_ts() -> int:
    return int(time.time())


def expected_origin() -> str:
    # for local demo:
    return f"http://{RP_ID}:{APP_PORT}"


# -----------------------------
# DB
# -----------------------------
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','user')),
        webauthn_user_id_b64 TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        user_id INTEGER PRIMARY KEY,
        balance INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

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
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('register','auth','tx')),
        challenge_b64 TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pending_tx (
        session_token TEXT PRIMARY KEY,
        from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )
    """)

    con.commit()

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


def get_user(username: str) -> Optional[sqlite3.Row]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def require_login():
    if not session.get("authed") or not session.get("username"):
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    return None


def get_logged_in_user() -> sqlite3.Row:
    u = get_user(session["username"])
    if not u:
        raise RuntimeError("Session user missing from DB")
    return u


def session_token() -> str:
    if "sess_token" not in session:
        session["sess_token"] = secrets.token_urlsafe(24)
    return session["sess_token"]


def store_challenge(user_id: int, kind: str, challenge_b64: str) -> None:
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO challenges(user_id, kind, challenge_b64, created_at) VALUES (?,?,?,?)",
        (user_id, kind, challenge_b64, now_ts()),
    )
    con.commit()
    con.close()


def latest_challenge(user_id: int, kind: str, max_age_sec: int = 180) -> Optional[str]:
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT challenge_b64, created_at FROM challenges WHERE user_id=? AND kind=? ORDER BY id DESC LIMIT 1",
        (user_id, kind),
    )
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    if now_ts() - row["created_at"] > max_age_sec:
        return None
    return row["challenge_b64"]


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


def update_cred_sign_count(user_id: int, cred_id_b64: str, new_sign_count: int, device_type: str, backed_up: bool):
    con = db()
    cur = con.cursor()
    cur.execute(
        "UPDATE credentials SET sign_count=?, device_type=?, backed_up=? WHERE user_id=? AND credential_id_b64=?",
        (new_sign_count, device_type, 1 if backed_up else 0, user_id, cred_id_b64),
    )
    con.commit()
    con.close()


def add_credential(user_id: int, verification) -> None:
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


def delete_credential(user_id: int, cred_id_b64: str) -> None:
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM credentials WHERE user_id=? AND credential_id_b64=?", (user_id, cred_id_b64))
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


def transfer_funds(from_user_id: int, to_user_id: int, amount: int) -> None:
    if amount <= 0:
        raise ValueError("Amount must be > 0")
    con = db()
    cur = con.cursor()
    cur.execute("SELECT balance FROM accounts WHERE user_id=?", (from_user_id,))
    fb = cur.fetchone()
    if not fb:
        raise ValueError("Sender account missing")
    if fb["balance"] < amount:
        raise ValueError("Insufficient funds")
    cur.execute("UPDATE accounts SET balance = balance - ? WHERE user_id=?", (amount, from_user_id))
    cur.execute("UPDATE accounts SET balance = balance + ? WHERE user_id=?", (amount, to_user_id))
    con.commit()
    con.close()


def put_pending_tx(from_user_id: int, to_user_id: int, amount: int) -> None:
    con = db()
    cur = con.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO pending_tx(session_token, from_user_id, to_user_id, amount, created_at) VALUES (?,?,?,?,?)",
        (session_token(), from_user_id, to_user_id, amount, now_ts()),
    )
    con.commit()
    con.close()


def pop_pending_tx():
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM pending_tx WHERE session_token=?", (session_token(),))
    row = cur.fetchone()
    cur.execute("DELETE FROM pending_tx WHERE session_token=?", (session_token(),))
    con.commit()
    con.close()
    return row


# -----------------------------
# UI (IMPORTANT: NOT an f-string)
# -----------------------------
HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Fingerprint Bank Demo</title>
  <style>
    body { font-family: system-ui, Segoe UI, Arial; margin: 24px; background:#0b0f14; color:#e9eef5; }
    .card { background:#121923; border:1px solid #233044; border-radius:16px; padding:16px; margin:12px 0; box-shadow: 0 6px 24px rgba(0,0,0,.25); }
    button { padding:10px 12px; border-radius:12px; border:1px solid #2a3a55; background:#182235; color:#e9eef5; cursor:pointer; }
    button:hover { background:#1c2a44; }
    input, select { padding:10px 12px; border-radius:12px; border:1px solid #2a3a55; background:#0f1622; color:#e9eef5; width: 260px; }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .muted { color:#9fb2cc; }
    pre { white-space: pre-wrap; background:#0f1622; padding:12px; border-radius:12px; border:1px solid #2a3a55; }
    .pill { display:inline-block; padding:4px 10px; border:1px solid #2a3a55; border-radius:999px; margin-left:8px; font-size:12px; color:#9fb2cc; }
  </style>
</head>
<body>
  <h2>Fingerprint Bank Demo <span class="pill">Windows Hello / WebAuthn</span></h2>

  <div class="card">
    <div class="row">
      <label class="muted">User:</label>
      <select id="username">
        <option value="user1">user1</option>
        <option value="user2">user2</option>
        <option value="admin">admin</option>
      </select>
      <button onclick="refresh()">Refresh status</button>
    </div>
    <p class="muted">Register up to <b>3</b> passkeys per user. Transfers require a fresh fingerprint prompt.</p>
    <div class="row">
      <button onclick="registerPasskey()">Register passkey (fingerprint slot)</button>
      <button onclick="login()">Login with fingerprint</button>
      <button onclick="logout()">Logout</button>
    </div>
    <div id="status" style="margin-top:10px;"></div>
  </div>

  <div class="card">
    <h3>Balances</h3>
    <div class="row">
      <button onclick="getBalances()">Load balances</button>
    </div>
    <pre id="balances"></pre>
  </div>

  <div class="card">
    <h3>Admin deposit (admin only)</h3>
    <div class="row">
      <label class="muted">To:</label>
      <select id="dep_to">
        <option value="user1">user1</option>
        <option value="user2">user2</option>
      </select>
      <label class="muted">Amount:</label>
      <input id="dep_amount" type="number" value="1000" />
      <button onclick="deposit()">Deposit</button>
    </div>
    <pre id="deposit_out"></pre>
  </div>

  <div class="card">
    <h3>Transfer (fingerprint required)</h3>
    <div class="row">
      <label class="muted">To:</label>
      <select id="tx_to">
        <option value="user2">user2</option>
        <option value="user1">user1</option>
      </select>
      <label class="muted">Amount:</label>
      <input id="tx_amount" type="number" value="200" />
      <button onclick="transfer()">Transfer with fingerprint</button>
    </div>
    <pre id="tx_out"></pre>
  </div>

  <div class="card">
    <h3>Passkeys (this user)</h3>
    <div class="row">
      <button onclick="listPasskeys()">List passkeys</button>
      <input id="del_cred" placeholder="credential_id_b64 (paste)" />
      <button onclick="deletePasskey()">Delete passkey</button>
    </div>
    <pre id="keys_out"></pre>
  </div>

<script>
function qs(id){ return document.getElementById(id); }

function b64urlToBuf(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
}

function credentialToJSON(cred) {
  if (!cred) return null;
  const res = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type
  };
  if (cred.response) {
    const r = cred.response;
    res.response = {};
    if (r.clientDataJSON) res.response.clientDataJSON = bufToB64url(r.clientDataJSON);
    if (r.attestationObject) res.response.attestationObject = bufToB64url(r.attestationObject);
    if (r.authenticatorData) res.response.authenticatorData = bufToB64url(r.authenticatorData);
    if (r.signature) res.response.signature = bufToB64url(r.signature);
    if (r.userHandle) res.response.userHandle = bufToB64url(r.userHandle);
    if (r.transports && typeof r.transports === 'function') res.response.transports = r.transports();
  }
  return res;
}

async function api(path, method="GET", body=null) {
  const opts = { method, headers: { "Content-Type":"application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  const data = await r.json().catch(()=>({ok:false,error:"Bad JSON"}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

async function refresh() {
  try {
    const s = await api("/api/status");
    qs("status").innerHTML = `<pre>${JSON.stringify(s, null, 2)}</pre>`;
  } catch(e) {
    qs("status").innerHTML = `<pre>${e.message}</pre>`;
  }
}

async function registerPasskey() {
  const username = qs("username").value;
  try {
    const r = await api("/api/webauthn/register/options", "POST", { username });
    const opts = r.publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    if (opts.excludeCredentials) {
      for (const c of opts.excludeCredentials) c.id = b64urlToBuf(c.id);
    }
    const cred = await navigator.credentials.create({ publicKey: opts });
    const payload = credentialToJSON(cred);
    const out = await api("/api/webauthn/register/verify", "POST", { username, credential: payload });
    qs("status").innerHTML = `<pre>${JSON.stringify(out, null, 2)}</pre>`;
  } catch(e) {
    qs("status").innerHTML = `<pre>${e.message}</pre>`;
  }
}

async function login() {
  const username = qs("username").value;
  try {
    const r = await api("/api/webauthn/auth/options", "POST", { username });
    const opts = r.publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.allowCredentials) {
      for (const c of opts.allowCredentials) c.id = b64urlToBuf(c.id);
    }
    const assertion = await navigator.credentials.get({ publicKey: opts });
    const payload = credentialToJSON(assertion);
    const out = await api("/api/webauthn/auth/verify", "POST", { username, credential: payload });
    qs("status").innerHTML = `<pre>${JSON.stringify(out, null, 2)}</pre>`;
  } catch(e) {
    qs("status").innerHTML = `<pre>${e.message}</pre>`;
  }
}

async function logout() {
  try {
    const out = await api("/api/logout", "POST", {});
    qs("status").innerHTML = `<pre>${JSON.stringify(out, null, 2)}</pre>`;
  } catch(e) {
    qs("status").innerHTML = `<pre>${e.message}</pre>`;
  }
}

async function getBalances() {
  try {
    const out = await api("/api/balances");
    qs("balances").textContent = JSON.stringify(out, null, 2);
  } catch(e) {
    qs("balances").textContent = e.message;
  }
}

async function deposit() {
  try {
    const to_username = qs("dep_to").value;
    const amount = parseInt(qs("dep_amount").value || "0", 10);
    const out = await api("/api/admin/deposit", "POST", { to_username, amount });
    qs("deposit_out").textContent = JSON.stringify(out, null, 2);
  } catch(e) {
    qs("deposit_out").textContent = e.message;
  }
}

async function transfer() {
  try {
    const to_username = qs("tx_to").value;
    const amount = parseInt(qs("tx_amount").value || "0", 10);

    const r = await api("/api/transfer/options", "POST", { to_username, amount });
    const opts = r.publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.allowCredentials) {
      for (const c of opts.allowCredentials) c.id = b64urlToBuf(c.id);
    }

    const assertion = await navigator.credentials.get({ publicKey: opts });
    const payload = credentialToJSON(assertion);

    const out = await api("/api/transfer/verify", "POST", { credential: payload });
    qs("tx_out").textContent = JSON.stringify(out, null, 2);
  } catch(e) {
    qs("tx_out").textContent = e.message;
  }
}

async function listPasskeys() {
  try {
    const out = await api("/api/credentials");
    qs("keys_out").textContent = JSON.stringify(out, null, 2);
  } catch(e) {
    qs("keys_out").textContent = e.message;
  }
}

async function deletePasskey() {
  try {
    const cred_id_b64 = qs("del_cred").value.trim();
    const out = await api("/api/credentials/delete", "POST", { cred_id_b64 });
    qs("keys_out").textContent = JSON.stringify(out, null, 2);
  } catch(e) {
    qs("keys_out").textContent = e.message;
  }
}

refresh();
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return Response(HTML, mimetype="text/html")


@app.get("/api/status")
def status():
    username = session.get("username")
    authed = bool(session.get("authed"))
    role = None
    if username:
        u = get_user(username)
        role = u["role"] if u else None
    return jsonify({"ok": True, "logged_in_as": username, "authed": authed, "role": role})


@app.post("/api/logout")
def logout():
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

    creds = list_creds(u["id"])
    if len(creds) >= 3:
        return jsonify({"ok": False, "error": "Max 3 passkeys per user reached"}), 400

    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    selection = AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.PREFERRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    opts = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=base64url_to_bytes(u["webauthn_user_id_b64"]),
        user_name=u["username"],
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=selection,
        exclude_credentials=exclude,
        timeout=60000,
    )

    opts_json = json.loads(options_to_json(opts))
    store_challenge(u["id"], "register", opts_json["challenge"])
    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/webauthn/register/verify")
def register_verify():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    credential = body.get("credential")
    u = get_user(username)
    if not u or not credential:
        return jsonify({"ok": False, "error": "Bad request"}), 400

    if len(list_creds(u["id"])) >= 3:
        return jsonify({"ok": False, "error": "Max 3 passkeys per user reached"}), 400

    ch_b64 = latest_challenge(u["id"], "register")
    if not ch_b64:
        return jsonify({"ok": False, "error": "Registration challenge expired. Try again."}), 400

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(ch_b64),
            expected_rp_id=RP_ID,
            expected_origin=expected_origin(),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Registration failed: {e}"}), 400

    add_credential(u["id"], verification)
    return jsonify({"ok": True, "message": "Passkey registered.", "total": len(list_creds(u["id"]))})


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

    creds = list_creds(u["id"])
    if not creds:
        return jsonify({"ok": False, "error": "No passkeys registered. Register first."}), 400

    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    opts = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    opts_json = json.loads(options_to_json(opts))
    store_challenge(u["id"], "auth", opts_json["challenge"])
    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/webauthn/auth/verify")
def auth_verify():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    credential = body.get("credential")
    u = get_user(username)
    if not u or not credential:
        return jsonify({"ok": False, "error": "Bad request"}), 400

    ch_b64 = latest_challenge(u["id"], "auth")
    if not ch_b64:
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
            expected_challenge=base64url_to_bytes(ch_b64),
            expected_rp_id=RP_ID,
            expected_origin=expected_origin(),
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
# Banking endpoints
# -----------------------------
@app.get("/api/balances")
def balances():
    maybe = require_login()
    if maybe:
        return maybe

    con = db()
    cur = con.cursor()
    cur.execute("""
      SELECT u.username, u.role, a.balance
      FROM users u JOIN accounts a ON a.user_id=u.id
      ORDER BY u.username
    """)
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify({"ok": True, "balances": rows, "logged_in_as": session["username"]})


@app.post("/api/admin/deposit")
def admin_deposit():
    maybe = require_login()
    if maybe:
        return maybe

    u = get_logged_in_user()
    if u["role"] != "admin":
        return jsonify({"ok": False, "error": "Admin only"}), 403

    body = request.get_json(force=True)
    to_username = (body.get("to_username") or "").strip()
    amount = int(body.get("amount") or 0)
    if amount <= 0:
        return jsonify({"ok": False, "error": "Amount must be > 0"}), 400

    tu = get_user(to_username)
    if not tu or tu["role"] != "user":
        return jsonify({"ok": False, "error": "Deposit target must be user1/user2"}), 400

    set_balance(tu["id"], get_balance(tu["id"]) + amount)
    return jsonify({"ok": True, "message": f"Deposited {amount} to {to_username}", "new_balance": get_balance(tu["id"])})


@app.post("/api/transfer/options")
def transfer_options():
    maybe = require_login()
    if maybe:
        return maybe

    u = get_logged_in_user()
    if u["role"] != "user":
        return jsonify({"ok": False, "error": "Only user accounts can transfer in this demo"}), 403

    body = request.get_json(force=True)
    to_username = (body.get("to_username") or "").strip()
    amount = int(body.get("amount") or 0)
    if amount <= 0:
        return jsonify({"ok": False, "error": "Amount must be > 0"}), 400

    tu = get_user(to_username)
    if not tu or tu["role"] != "user":
        return jsonify({"ok": False, "error": "Transfer target must be user1/user2"}), 400
    if tu["id"] == u["id"]:
        return jsonify({"ok": False, "error": "Cannot transfer to yourself"}), 400

    put_pending_tx(u["id"], tu["id"], amount)

    creds = list_creds(u["id"])
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id_b64"])) for c in creds]

    opts = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    opts_json = json.loads(options_to_json(opts))
    store_challenge(u["id"], "tx", opts_json["challenge"])
    return jsonify({"ok": True, "publicKey": opts_json})


@app.post("/api/transfer/verify")
def transfer_verify():
    maybe = require_login()
    if maybe:
        return maybe

    u = get_logged_in_user()
    if u["role"] != "user":
        return jsonify({"ok": False, "error": "Only user accounts can transfer in this demo"}), 403

    body = request.get_json(force=True)
    credential = body.get("credential")
    if not credential:
        return jsonify({"ok": False, "error": "Missing credential"}), 400

    pending = pop_pending_tx()
    if not pending:
        return jsonify({"ok": False, "error": "No pending transfer found. Start again."}), 400

    ch_b64 = latest_challenge(u["id"], "tx")
    if not ch_b64:
        return jsonify({"ok": False, "error": "Transfer challenge expired. Try again."}), 400

    cred_id_b64 = credential.get("id")
    if not cred_id_b64:
        return jsonify({"ok": False, "error": "Missing credential id"}), 400

    cred_row = get_cred_by_id(u["id"], cred_id_b64)
    if not cred_row:
        return jsonify({"ok": False, "error": "Unknown credential for this user"}), 400

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(ch_b64),
            expected_rp_id=RP_ID,
            expected_origin=expected_origin(),
            credential_public_key=base64url_to_bytes(cred_row["public_key_b64"]),
            credential_current_sign_count=int(cred_row["sign_count"]),
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Fingerprint verification failed: {e}"}), 400

    update_cred_sign_count(
        u["id"], cred_id_b64, int(verification.new_sign_count),
        getattr(verification, "credential_device_type", None),
        bool(getattr(verification, "credential_backed_up", False)),
    )

    try:
        transfer_funds(int(pending["from_user_id"]), int(pending["to_user_id"]), int(pending["amount"]))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({"ok": True, "message": f"Transfer complete: {pending['amount']}", "your_new_balance": get_balance(u["id"])})


@app.get("/api/credentials")
def credentials():
    maybe = require_login()
    if maybe:
        return maybe

    u = get_logged_in_user()
    rows = list_creds(u["id"])
    out = []
    for r in rows:
        out.append({
            "credential_id_b64": r["credential_id_b64"],
            "sign_count": int(r["sign_count"]),
            "created_at": int(r["created_at"]),
            "device_type": r["device_type"],
            "backed_up": bool(r["backed_up"]) if r["backed_up"] is not None else None,
        })
    return jsonify({"ok": True, "username": u["username"], "count": len(out), "passkeys": out})


@app.post("/api/credentials/delete")
def credentials_delete():
    maybe = require_login()
    if maybe:
        return maybe

    u = get_logged_in_user()
    body = request.get_json(force=True)
    cred_id_b64 = (body.get("cred_id_b64") or "").strip()
    if not cred_id_b64:
        return jsonify({"ok": False, "error": "Missing cred_id_b64"}), 400

    if not get_cred_by_id(u["id"], cred_id_b64):
        return jsonify({"ok": False, "error": "Credential not found for this user"}), 404

    delete_credential(u["id"], cred_id_b64)
    return jsonify({"ok": True, "message": "Deleted", "remaining": len(list_creds(u["id"]))})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=APP_PORT, debug=True)
