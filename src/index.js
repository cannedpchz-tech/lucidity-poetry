const encoder = new TextEncoder();

const COOKIE = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

const json = (data, status = 200, headers = {}) => new Response(
  JSON.stringify(data),
  {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers
    }
  }
);

function htmlEscape(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[c]));
}

function randomHex(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value) {
  return [...new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(value))
  )]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password, saltHex = null) {
  const salt = saltHex
    ? Uint8Array.from((saltHex.match(/../g) || []).map(x => parseInt(x, 16)))
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 150000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return (
    [...salt].map(x => x.toString(16).padStart(2, "0")).join("") +
    ":" +
    [...new Uint8Array(bits)]
      .map(x => x.toString(16).padStart(2, "0"))
      .join("")
  );
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;

  const [salt, hash] = stored.split(":");
  return (await hashPassword(password, salt)) === `${salt}:${hash}`;
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  const item = cookies
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(COOKIE + "="));

  return item
    ? decodeURIComponent(item.slice(COOKIE.length + 1))
    : null;
}

function makeCookie(token, maxAge = SESSION_SECONDS) {
  return `${COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/*
  This supports the database structure already in your project.

  It can work with either:
  - is_admin
  - role

  And it can use either:
  - session_token on users
  - a sessions table

  That means we don't need to delete or recreate your D1 database.
*/

let databaseInfoPromise = null;

async function getDatabaseInfo(env) {
  if (!databaseInfoPromise) {
    databaseInfoPromise = (async () => {
      const usersInfo = await env.DB
        .prepare("PRAGMA table_info(users)")
        .all();

      const usersColumns = new Set(
        (usersInfo.results || []).map(x => x.name)
      );

      const poemsInfo = await env.DB
        .prepare("PRAGMA table_info(poems)")
        .all();

      const poemsColumns = new Set(
        (poemsInfo.results || []).map(x => x.name)
      );

      return {
        usersColumns,
        poemsColumns,
        hasAdminColumn: usersColumns.has("is_admin"),
        hasRoleColumn: usersColumns.has("role"),
        hasSessionToken: usersColumns.has("session_token")
      };
    })();
  }

  return databaseInfoPromise;
}

async function ensureSessionsTable(env, info) {
  if (info.hasSessionToken) return;

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash)
  `).run();
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token) return null;

  const info = await getDatabaseInfo(env);

  if (info.hasSessionToken) {
    const hash = await sha256(token);

    const columns = info.hasAdminColumn
      ? "id, username, is_admin"
      : "id, username, role";

    const user = await env.DB
      .prepare(
        `SELECT ${columns}
         FROM users
         WHERE session_token = ?`
      )
      .bind(hash)
      .first();

    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      is_admin: info.hasAdminColumn
        ? !!user.is_admin
        : user.role === "admin"
    };
  }

  await ensureSessionsTable(env, info);

  const user = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username,
        ${info.hasAdminColumn ? "u.is_admin" : "u.role"}
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND s.expires_at > ?
    `)
    .bind(
      await sha256(token),
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!user) return null;

  return {
    id: user.id,
    username: user.username,
    is_admin: info.hasAdminColumn
      ? !!user.is_admin
      : user.role === "admin"
  };
}

async function createSession(userId, env) {
  const token = randomHex(32);
  const info = await getDatabaseInfo(env);

  if (info.hasSessionToken) {
    await env.DB
      .prepare("UPDATE users SET session_token = ? WHERE id = ?")
      .bind(await sha256(token), userId)
      .run();

    return token;
  }

  await ensureSessionsTable(env, info);

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
         OR expires_at <= ?
    `)
    .bind(userId, Math.floor(Date.now() / 1000))
    .run();

  await env.DB
    .prepare(`
      INSERT INTO sessions(token_hash, user_id, expires_at)
      VALUES (?, ?, ?)
    `)
    .bind(
      await sha256(token),
      userId,
      Math.floor(Date.now() / 1000) + SESSION_SECONDS
    )
    .run();

  return token;
}

async function deleteSession(request, env) {
  const token = getCookie(request);

  if (!token) return;

  const info = await getDatabaseInfo(env);
  const hash = await sha256(token);

  if (info.hasSessionToken) {
    await env.DB
      .prepare("UPDATE users SET session_token = NULL WHERE session_token = ?")
      .bind(hash)
      .run();

    return;
  }

  await ensureSessionsTable(env, info);

  await env.DB
    .prepare("DELETE FROM sessions WHERE token_hash = ?")
    .bind(hash)
    .run();
}

async function createUser(env, username, password) {
  const info = await getDatabaseInfo(env);

  const existing = await env.DB
    .prepare(
      "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
    )
    .bind(username)
    .first();

  if (existing) {
    throw new Error("That username is already taken.");
  }

  const countResult = await env.DB
    .prepare("SELECT COUNT(*) AS count FROM users")
    .first();

  const isFirstUser = Number(countResult?.count || 0) === 0;
  const passwordHash = await hashPassword(password);

  let result;

  if (info.hasAdminColumn) {
    result = await env.DB
      .prepare(`
        INSERT INTO users(username, password_hash, is_admin)
        VALUES (?, ?, ?)
      `)
      .bind(
        username,
        passwordHash,
        isFirstUser ? 1 : 0
      )
      .run();
  } else if (info.hasRoleColumn) {
    result = await env.DB
      .prepare(`
        INSERT INTO users(username, password_hash, role)
        VALUES (?, ?, ?)
      `)
      .bind(
        username,
        passwordHash,
        isFirstUser ? "admin" : "user"
      )
      .run();
  } else {
    throw new Error(
      "The users table is missing its admin/role column."
    );
  }

  return {
    id: result.meta.last_row_id,
    is_admin: isFirstUser
  };
}

function appHTML() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#f4efe6">
<title>Lucidity — Poetry by Juan Pablo F.</title>

<style>
:root{
  --paper:#f4efe6;
  --ink:#1b1a18;
  --muted:#746f66;
  --line:#d8d0c3;
  --card:#fbf8f1;
  --accent:#6e4e8f;
  --accent2:#8b6ca8;
  --danger:#9d3d3d;
  --shadow:0 14px 45px rgba(35,28,18,.08)
}

*{box-sizing:border-box}

html{scroll-behavior:smooth}

body{
  margin:0;
  background:var(--paper);
  color:var(--ink);
  font-family:Georgia,"Times New Roman",serif
}

button,input,textarea{
  font:inherit
}

.site{
  max-width:1120px;
  margin:auto;
  padding:0 22px
}

.top{
  border-bottom:1px solid var(--line);
  background:rgba(244,239,230,.9);
  backdrop-filter:blur(12px);
  position:sticky;
  top:0;
  z-index:10
}

.nav{
  height:72px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px
}

.brand{
  font-size:23px;
  font-weight:bold;
  letter-spacing:.3px
}

.brand small{
  display:block;
  font-family:system-ui,sans-serif;
  color:var(--muted);
  font-size:9px;
  letter-spacing:3px;
  text-transform:uppercase;
  margin-top:1px
}

.navRight{
  display:flex;
  align-items:center;
  gap:10px
}

.pill{
  font:600 12px system-ui,sans-serif;
  color:var(--muted)
}

.hero{
  padding:78px 0 62px;
  display:grid;
  grid-template-columns:1.4fr .8fr;
  gap:55px;
  align-items:end
}

.eyebrow{
  font:700 11px system-ui,sans-serif;
  letter-spacing:3px;
  text-transform:uppercase;
  color:var(--accent);
  margin-bottom:18px
}

.hero h1{
  font-size:clamp(52px,8vw,92px);
  line-height:.88;
  margin:0;
  letter-spacing:-3px;
  font-weight:500
}

.hero p{
  font-size:20px;
  line-height:1.55;
  color:var(--muted);
  margin:0 0 4px
}

.credit{
  margin-top:18px;
  color:var(--muted);
  font:12px system-ui,sans-serif
}

.rule{
  height:1px;
  background:var(--line)
}

.toolbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  padding:24px 0 18px;
  gap:12px
}

.toolbar h2{
  font-size:20px;
  font-weight:500;
  margin:0
}

.buttons{
  display:flex;
  gap:9px;
  flex-wrap:wrap
}

button{
  cursor:pointer;
  border:1px solid var(--ink);
  border-radius:999px;
  padding:10px 16px;
  background:var(--ink);
  color:#fff;
  font-family:system-ui,sans-serif;
  font-size:13px;
  font-weight:700
}

button.secondary{
  background:transparent;
  color:var(--ink);
  border-color:var(--line)
}

button.danger{
  background:transparent;
  color:var(--danger);
  border-color:#d7aaa5
}

.feed{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:18px;
  padding-bottom:90px
}

.poem{
  background:var(--card);
  border:1px solid var(--line);
  padding:28px;
  border-radius:3px;
  box-shadow:var(--shadow);
  min-height:260px;
  display:flex;
  flex-direction:column
}

.poem.admin{
  border-top:3px solid var(--accent)
}

.poemTitle{
  font-size:29px;
  line-height:1.1;
  margin:0 0 8px;
  font-weight:500
}

.meta{
  font:12px system-ui,sans-serif;
  color:var(--muted);
  margin-bottom:22px
}

.poemBody{
  white-space:pre-wrap;
  line-height:1.85;
  font-size:17px;
  flex:1
}

.actions{
  display:flex;
  gap:8px;
  margin-top:24px
}

.empty{
  grid-column:1/-1;
  padding:65px 20px;
  text-align:center;
  border:1px dashed var(--line);
  color:var(--muted);
  font-size:17px
}

dialog{
  width:min(580px,calc(100% - 28px));
  border:1px solid var(--line);
  background:var(--card);
  color:var(--ink);
  padding:0;
  border-radius:4px;
  box-shadow:0 30px 100px rgba(0,0,0,.25)
}

dialog::backdrop{
  background:rgba(25,20,15,.5);
  backdrop-filter:blur(3px)
}

.modal{
  padding:30px
}

.modal h2{
  font-size:34px;
  font-weight:500;
  margin:0 0 4px
}

.sub{
  color:var(--muted);
  font:13px system-ui,sans-serif;
  margin-bottom:22px
}

label{
  display:block;
  font:700 12px system-ui,sans-serif;
  letter-spacing:1px;
  text-transform:uppercase;
  color:var(--muted);
  margin:15px 0 7px
}

input,textarea{
  width:100%;
  border:1px solid var(--line);
  background:#fffdf8;
  color:var(--ink);
  padding:13px;
  border-radius:2px;
  outline:none
}

input:focus,textarea:focus{
  border-color:var(--accent)
}

textarea{
  min-height:260px;
  resize:vertical;
  line-height:1.7
}

.formActions{
  display:flex;
  justify-content:flex-end;
  gap:9px;
  margin-top:20px
}

.error{
  min-height:20px;
  color:var(--danger);
  font:13px system-ui,sans-serif;
  margin-top:10px
}

.switch{
  font:13px system-ui,sans-serif;
  color:var(--muted);
  text-align:center;
  margin:18px 0 0
}

.switch a{
  color:var(--accent);
  font-weight:700;
  cursor:pointer
}

.toast{
  position:fixed;
  left:50%;
  bottom:24px;
  transform:translateX(-50%);
  background:var(--ink);
  color:#fff;
  padding:12px 17px;
  border-radius:999px;
  font:13px system-ui,sans-serif;
  opacity:0;
  pointer-events:none;
  transition:.2s;
  z-index:50
}

.toast.show{
  opacity:1
}

.loading{
  color:var(--muted);
  font:13px system-ui,sans-serif;
  padding:20px 0
}

@media(max-width:760px){
  .hero{
    grid-template-columns:1fr;
    gap:24px;
    padding:55px 0 45px
  }

  .hero h1{
    letter-spacing:-2px
  }

  .feed{
    grid-template-columns:1fr
  }

  .nav{
    height:64px
  }

  .pill{
    display:none
  }

  .site{
    padding:0 15px
  }

  .poem{
    padding:23px
  }
}
</style>
</head>

<body>

<header class="top">
<nav class="site nav">
  <div class="brand">
    Lucidity
    <small>Poetry Archive</small>
  </div>

  <div class="navRight">
    <span class="pill" id="who"></span>
    <button class="secondary" id="authButton">Log in</button>
  </div>
</nav>
</header>

<main class="site">

<section class="hero">

  <div>
    <div class="eyebrow">A place for words</div>

    <h1>
      Write what<br>
      you cannot say.
    </h1>

    <div class="credit">
      A poetry archive by Juan Pablo F.
    </div>
  </div>

  <p>
    Poems by people who wanted their words
    to exist somewhere outside their heads.
  </p>

</section>

<div class="rule"></div>

<section class="toolbar">
  <h2>Recent poems</h2>

  <div class="buttons">
    <button id="newButton">Write a poem</button>
  </div>
</section>

<section id="feed" class="feed">
  <div class="loading">Loading poems…</div>
</section>

</main>

<div id="toast" class="toast"></div>

<dialog id="authDialog">

<div class="modal">

<h2 id="authHeading">Log in</h2>

<div class="sub" id="authSub">
Return to your writing.
</div>

<form id="authForm">

<label>Username</label>

<input
  id="username"
  autocomplete="username"
  required
  minlength="3"
  maxlength="30"
>

<label>Password</label>

<input
  id="password"
  type="password"
  autocomplete="current-password"
  required
  minlength="8"
>

<div id="authError" class="error"></div>

<div class="formActions">

<button
  type="button"
  class="secondary"
  id="authCancel"
>
Cancel
</button>

<button id="authSubmit">
Log in
</button>

</div>

</form>

<div class="switch">

<span id="switchLabel">New here?</span>

<a id="switchAuth">
Create an account
</a>

</div>

</div>

</dialog>

<dialog id="poemDialog">

<div class="modal">

<h2 id="poemHeading">
Write a poem
</h2>

<div class="sub">
Put it here. You can change or remove it later.
</div>

<form id="poemForm">

<label>Title</label>

<input
  id="poemTitle"
  maxlength="120"
  required
>

<label>Your poem</label>

<textarea
  id="poemBody"
  maxlength="20000"
  required
></textarea>

<div id="poemError" class="error"></div>

<div class="formActions">

<button
  type="button"
  class="secondary"
  id="poemCancel"
>
Cancel
</button>

<button id="poemSubmit">
Publish poem
</button>

</div>

</form>

</div>

</dialog>

<script>
(function(){

  const state = {
    user: null,
    editingId: null,
    authMode: "login"
  };

  const $ = id => document.getElementById(id);

  const esc = value =>
    String(value ?? "").replace(/[&<>"']/g, c => ({
      "&":"&amp;",
      "<":"&lt;",
      ">":"&gt;",
      "\"":"&quot;",
      "'":"&#39;"
    }[c]));

  async function api(url, options = {}) {

    const headers = {
      "content-type": "application/json",
      ...(options.headers || {})
    };

    const response = await fetch(url, {
      ...options,
      headers
    });

    let data = {};

    try {
      data = await response.json();
    } catch {}

    if (!response.ok) {
      throw new Error(
        data.error || `Request failed (${response.status})`
      );
    }

    return data;
  }

  function toast(message) {

    const element = $("toast");

    element.textContent = message;
    element.classList.add("show");

    clearTimeout(toast.timer);

    toast.timer = setTimeout(() => {
      element.classList.remove("show");
    }, 2500);
  }

  function openAuth(mode = "login") {

    state.authMode = mode;

    renderAuth();

    $("authDialog").showModal();

    setTimeout(() => {
      $("username").focus();
    }, 50);
  }

  function renderAuth() {

    const register = state.authMode === "register";

    $("authHeading").textContent =
      register ? "Create an account" : "Log in";

    $("authSub").textContent =
      register
        ? "Create a place for your words."
        : "Return to your writing.";

    $("authSubmit").textContent =
      register ? "Create account" : "Log in";

    $("switchLabel").textContent =
      register
        ? "Already have an account?"
        : "New here?";

    $("switchAuth").textContent =
      register
        ? "Log in"
        : "Create an account";

    $("authError").textContent = "";
  }

  function openNew() {

    if (!state.user) {
      openAuth("login");
      return;
    }

    state.editingId = null;

    $("poemHeading").textContent = "Write a poem";
    $("poemSubmit").textContent = "Publish poem";

    $("poemTitle").value = "";
    $("poemBody").value = "";
    $("poemError").textContent = "";

    $("poemDialog").showModal();
  }

  function openEdit(id, title, body) {

    state.editingId = id;

    $("poemHeading").textContent = "Edit poem";
    $("poemSubmit").textContent = "Save changes";

    $("poemTitle").value = title;
    $("poemBody").value = body;

    $("poemError").textContent = "";

    $("poemDialog").showModal();
  }

  async function refreshUser() {

    const data = await api("/api/me");

    state.user = data.user;

    if (state.user) {

      $("who").textContent =
        "@" +
        state.user.username +
        (state.user.is_admin ? " · ADMIN" : "");

      $("authButton").textContent = "Log out";

    } else {

      $("who").textContent = "";
      $("authButton").textContent = "Log in";
    }
  }

  async function loadPoems() {

    const data = await api("/api/poems");

    const feed = $("feed");

    if (!data.poems || !data.poems.length) {

      feed.innerHTML = `
        <div class="empty">
          No poems yet.<br><br>
          Be the first person to leave a few words here.
        </div>
      `;

      return;
    }

    feed.innerHTML = data.poems.map(poem => {

      const canModify =
        state.user &&
        (
          state.user.is_admin ||
          Number(state.user.id) === Number(poem.user_id)
        );

      const adminClass =
        state.user && state.user.is_admin
          ? "admin"
          : "";

      const editButton = canModify
        ? `
          <button
            class="secondary edit"
            data-id="${poem.id}"
            data-title="${encodeURIComponent(poem.title)}"
            data-body="${encodeURIComponent(poem.body)}"
          >
            Edit
          </button>
        `
        : "";

      const deleteButton = canModify
        ? `
          <button
            class="danger delete"
            data-id="${poem.id}"
          >
            Delete
          </button>
        `
        : "";

      const actions =
        canModify
          ? `
            <div class="actions">
              ${editButton}
              ${deleteButton}
            </div>
          `
          : "";

      return `
        <article class="poem ${adminClass}">

          <h3 class="poemTitle">
            ${esc(poem.title)}
          </h3>

          <div class="meta">
            by @${esc(poem.username)}
            · ${esc(poem.updated_at || poem.created_at || "")}
          </div>

          <div class="poemBody">
            ${esc(poem.body)}
          </div>

          ${actions}

        </article>
      `;

    }).join("");

    feed.querySelectorAll(".edit").forEach(button => {

      button.addEventListener("click", () => {

        openEdit(
          Number(button.dataset.id),
          decodeURIComponent(button.dataset.title),
          decodeURIComponent(button.dataset.body)
        );

      });

    });

    feed.querySelectorAll(".delete").forEach(button => {

      button.addEventListener("click", async () => {

        if (
          !confirm(
            "Delete this poem? This cannot be undone."
          )
        ) {
          return;
        }

        try {

          await api(
            "/api/poems/" + button.dataset.id,
            {
              method: "DELETE"
            }
          );

          toast("Poem deleted.");

          await loadPoems();

        } catch (error) {

          toast(error.message);
        }

      });

    });
  }

  $("authButton").addEventListener(
    "click",
    async () => {

      if (!state.user) {

        openAuth("login");
        return;
      }

      try {

        await api(
          "/api/logout",
          {
            method: "POST"
          }
        );

        state.user = null;

        await refreshUser();
        await loadPoems();

        toast("Logged out.");

      } catch (error) {

        toast(error.message);
      }
    }
  );

  $("newButton").addEventListener(
    "click",
    openNew
  );

  $("authCancel").addEventListener(
    "click",
    () => $("authDialog").close()
  );

  $("poemCancel").addEventListener(
    "click",
    () => $("poemDialog").close()
  );

  $("switchAuth").addEventListener(
    "click",
    () => {

      state.authMode =
        state.authMode === "login"
          ? "register"
          : "login";

      renderAuth();
    }
  );

  $("authForm").addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      $("authError").textContent = "";

      const username =
        $("username").value.trim();

      const password =
        $("password").value;

      try {

        await api(
          "/api/" + state.authMode,
          {
            method: "POST",
            body: JSON.stringify({
              username,
              password
            })
          }
        );

        $("authDialog").close();

        $("authForm").reset();

        await refreshUser();
        await loadPoems();

        toast(
          state.authMode === "register"
            ? "Account created."
            : "Welcome back."
        );

      } catch (error) {

        $("authError").textContent =
          error.message;
      }
    }
  );

  $("poemForm").addEventListener(
    "submit",
    async event => {

      event.preventDefault();

      $("poemError").textContent = "";

      const title =
        $("poemTitle").value.trim();

      const body =
        $("poemBody").value;

      try {

        if (state.editingId) {

          await api(
            "/api/poems/" + state.editingId,
            {
              method: "PUT",
              body: JSON.stringify({
                title,
                body
              })
            }
          );

        } else {

          await api(
            "/api/poems",
            {
              method: "POST",
              body: JSON.stringify({
                title,
                body
              })
            }
          );
        }

        $("poemDialog").close();

        await loadPoems();

        toast(
          state.editingId
            ? "Poem updated."
            : "Poem published."
        );

        state.editingId = null;

      } catch (error) {

        $("poemError").textContent =
          error.message;
      }
    }
  );

  async function start() {

    try {

      await refreshUser();

      await loadPoems();

    } catch (error) {

      console.error(error);

      $("feed").innerHTML = `
        <div class="empty">
          The site could not load its data.<br><br>
          <small>${esc(error.message)}</small>
        </div>
      `;
    }
  }

  start();

})();
</script>

</body>
</html>`;
}

export default {

  async fetch(request, env) {

    const url = new URL(request.url);

    try {

      /*
       * MAIN WEBSITE
       */

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {

        return new Response(
          appHTML(),
          {
            headers: {
              "content-type":
                "text/html; charset=UTF-8",
              "cache-control": "no-store"
            }
          }
        );
      }

      /*
       * CURRENT USER
       */

      if (
        request.method === "GET" &&
        url.pathname === "/api/me"
      ) {

        return json({
          user: await getUser(request, env)
        });
      }

      /*
       * REGISTER
       */

      if (
        request.method === "POST" &&
        url.pathname === "/api/register"
      ) {

        let body;

        try {
          body = await request.json();
        } catch {
          return json(
            { error: "Invalid request." },
            400
          );
        }

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        if (
          !/^[A-Za-z0-9_]{3,30}$/.test(username)
        ) {

          return json(
            {
              error:
                "Username must be 3–30 characters using letters, numbers, or underscores."
            },
            400
          );
        }

        if (password.length < 8) {

          return json(
            {
              error:
                "Password must be at least 8 characters."
            },
            400
          );
        }

        try {

          const user =
            await createUser(
              env,
              username,
              password
            );

          const session =
            await createSession(
              user.id,
              env
            );

          return json(
            {
              ok: true,
              user: {
                id: user.id,
                username,
                is_admin: user.is_admin
              }
            },
            200,
            {
              "set-cookie":
                makeCookie(session)
            }
          );

        } catch (error) {

          console.error(
            "REGISTER ERROR:",
            error
          );

          if (
            String(error.message || "")
              .toLowerCase()
              .includes("unique")
          ) {

            return json(
              {
                error:
                  "That username is already taken."
              },
              409
            );
          }

          return json(
            {
              error:
                error.message ||
                "Could not create account."
            },
            500
          );
        }
      }

      /*
       * LOGIN
       */

      if (
        request.method === "POST" &&
        url.pathname === "/api/login"
      ) {

        let body;

        try {
          body = await request.json();
        } catch {
          return json(
            { error: "Invalid request." },
            400
          );
        }

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        const info =
          await getDatabaseInfo(env);

        const columns =
          info.hasAdminColumn
           
