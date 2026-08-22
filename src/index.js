const COOKIE = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

/* =========================
   HELPERS
========================= */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, function (char) {
    const map = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    };

    return map[char];
  });
}

function randomHex(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  return Array.from(array)
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");
}

async function hashPassword(password, saltHex) {
  let salt;

  if (saltHex) {
    const parts = saltHex.match(/../g) || [];

    salt = new Uint8Array(
      parts.map(function (part) {
        return parseInt(part, 16);
      })
    );
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16));
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const saltString = Array.from(salt)
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");

  const hashString = Array.from(new Uint8Array(bits))
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");

  return saltString + ":" + hashString;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) {
    return false;
  }

  const pieces = stored.split(":");
  const salt = pieces[0];
  const expectedHash = pieces[1];

  const actual = await hashPassword(password, salt);

  return actual === salt + ":" + expectedHash;
}

/* =========================
   COOKIES / SESSIONS
========================= */

function getCookie(request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const part = cookie.trim();

    if (part.startsWith(COOKIE + "=")) {
      return decodeURIComponent(
        part.substring(COOKIE.length + 1)
      );
    }
  }

  return null;
}

function makeCookie(token, maxAge = SESSION_SECONDS) {
  return (
    COOKIE +
    "=" +
    encodeURIComponent(token) +
    "; Max-Age=" +
    maxAge +
    "; Path=/; HttpOnly; Secure; SameSite=Lax"
  );
}

/* =========================
   DATABASE
========================= */

async function setupDatabase(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS poems (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash)
  `).run();
}

async function createSession(userId, env) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);

  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE user_id = ? OR expires_at <= ?
  `)
    .bind(userId, Math.floor(Date.now() / 1000))
    .run();

  await env.DB.prepare(`
    INSERT INTO sessions
    (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(tokenHash, userId, expiresAt)
    .run();

  return token;
}

async function deleteSession(request, env) {
  const token = getCookie(request);

  if (!token) {
    return;
  }

  const tokenHash = await sha256(token);

  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE token_hash = ?
  `)
    .bind(tokenHash)
    .run();
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const session = await env.DB.prepare(`
    SELECT
      u.id,
      u.username,
      u.is_admin
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
  `)
    .bind(
      tokenHash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!session) {
    return null;
  }

  return {
    id: session.id,
    username: session.username,
    is_admin: Boolean(session.is_admin)
  };
}

/* =========================
   WEBSITE
========================= */

function appHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#f4efe6">

<title>Lucidity — Poetry Archive</title>

<style>
:root {
  --paper: #f4efe6;
  --card: #fbf8f1;
  --ink: #1b1a18;
  --muted: #746f66;
  --line: #d8d0c3;
  --accent: #6e4e8f;
  --danger: #9d3d3d;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: Georgia, "Times New Roman", serif;
}

button,
input,
textarea {
  font: inherit;
}

button {
  cursor: pointer;
  border: 1px solid var(--ink);
  border-radius: 999px;
  padding: 10px 16px;
  background: var(--ink);
  color: white;
  font-family: system-ui, sans-serif;
  font-size: 13px;
  font-weight: 700;
}

button.secondary {
  background: transparent;
  color: var(--ink);
  border-color: var(--line);
}

button.danger {
  background: transparent;
  color: var(--danger);
  border-color: #d7aaa5;
}

.site {
  max-width: 1120px;
  margin: auto;
  padding: 0 22px;
}

.top {
  border-bottom: 1px solid var(--line);
  background: rgba(244,239,230,.96);
  position: sticky;
  top: 0;
  z-index: 10;
}

.nav {
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.brand {
  font-size: 23px;
  font-weight: bold;
}

.brand small {
  display: block;
  font-family: system-ui, sans-serif;
  color: var(--muted);
  font-size: 9px;
  letter-spacing: 3px;
  text-transform: uppercase;
}

.navRight {
  display: flex;
  align-items: center;
  gap: 10px;
}

.pill {
  font: 600 12px system-ui, sans-serif;
  color: var(--muted);
}

.hero {
  padding: 78px 0 62px;
  display: grid;
  grid-template-columns: 1.4fr .8fr;
  gap: 55px;
  align-items: end;
}

.eyebrow {
  font: 700 11px system-ui, sans-serif;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 18px;
}

.hero h1 {
  font-size: clamp(52px, 8vw, 92px);
  line-height: .88;
  margin: 0;
  letter-spacing: -3px;
  font-weight: 500;
}

.hero p {
  font-size: 20
