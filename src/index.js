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
  font-size: 20px;
  line-height: 1.55;
  color: var(--muted);
}

.credit {
  margin-top: 18px;
  font: 12px system-ui, sans-serif;
  color: var(--muted);
}

.rule {
  height: 1px;
  background: var(--line);
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px 0 18px;
}

.toolbar h2 {
  font-size: 20px;
  font-weight: 500;
  margin: 0;
}

.feed {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
  padding-bottom: 90px;
}

.poem {
  background: var(--card);
  border: 1px solid var(--line);
  padding: 28px;
  box-shadow: 0 14px 45px rgba(35,28,18,.08);
  min-height: 260px;
  display: flex;
  flex-direction: column;
}

.poemTitle {
  font-size: 29px;
  line-height: 1.1;
  margin: 0 0 8px;
  font-weight: 500;
}

.meta {
  font: 12px system-ui, sans-serif;
  color: var(--muted);
  margin-bottom: 22px;
}

.poemBody {
  white-space: pre-wrap;
  line-height: 1.85;
  font-size: 17px;
  flex: 1;
}

.actions {
  display: flex;
  gap: 8px;
  margin-top: 24px;
}

.empty {
  grid-column: 1 / -1;
  padding: 65px 20px;
  text-align: center;
  border: 1px dashed var(--line);
  color: var(--muted);
}

dialog {
  width: min(580px, calc(100% - 28px));
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--ink);
  padding: 0;
  border-radius: 4px;
}

dialog::backdrop {
  background: rgba(25,20,15,.5);
}

.modal {
  padding: 30px;
}

.modal h2 {
  font-size: 34px;
  font-weight: 500;
  margin: 0 0 4px;
}

.sub {
  color: var(--muted);
  font: 13px system-ui, sans-serif;
  margin-bottom: 22px;
}

label {
  display: block;
  font: 700 12px system-ui, sans-serif;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--muted);
  margin: 15px 0 7px;
}

input,
textarea {
  width: 100%;
  border: 1px solid var(--line);
  background: #fffdf8;
  color: var(--ink);
  padding: 13px;
  border-radius: 2px;
  outline: none;
}

textarea {
  min-height: 240px;
  resize: vertical;
}

.formActions {
  display: flex;
  justify-content: flex-end;
  gap: 9px;
  margin-top: 20px;
}

.error {
  min-height: 20px;
  color: var(--danger);
  font: 13px system-ui, sans-serif;
  margin-top: 10px;
}

.switch {
  font: 13px system-ui, sans-serif;
  color: var(--muted);
  text-align: center;
  margin-top: 18px;
}

.switch a {
  color: var(--accent);
  font-weight: bold;
  cursor: pointer;
}

.toast {
  position: fixed;
  left: 50%;
  bottom: 24px;
  transform: translateX(-50%);
  background: var(--ink);
  color: white;
  padding: 12px 17px;
  border-radius: 999px;
  font: 13px system-ui, sans-serif;
  opacity: 0;
  transition: .2s;
  z-index: 50;
}

.toast.show {
  opacity: 1;
}

@media (max-width: 760px) {
  .hero {
    grid-template-columns: 1fr;
    gap: 20px;
    padding: 55px 0 45px;
  }

  .feed {
    grid-template-columns: 1fr;
  }

  .site {
    padding: 0 15px;
  }

  .nav {
    height: 64px;
  }

  .pill {
    display: none;
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
    Poems by people who wanted their words to exist
    somewhere outside their heads.
  </p>

</section>

<div class="rule"></div>

<section class="toolbar">
  <h2>Recent poems</h2>
  <button id="newButton">Write a poem</button>
</section>

<section id="feed" class="feed">
  <div class="empty">Loading poems...</div>
</section>

</main>

<div id="toast" class="toast"></div>

<!-- LOGIN / REGISTER -->

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
  required
  minlength="3"
  maxlength="30"
  autocomplete="username"
>

<label>Password</label>

<input
  id="password"
  type="password"
  required
  minlength="8"
  autocomplete="current-password"
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

<span id="switchLabel">
  New here?
</span>

<a id="switchAuth">
  Create an account
</a>

</div>

</div>

</dialog>

<!-- POEM EDITOR -->

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

const state = {
  user: null,
  editingId: null,
  authMode: "login"
};

function $(id) {
  return document.getElementById(id);
}

function escapeText(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

async function api(url, options = {}) {

  const config = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  };

  const response = await fetch(url, config);

  let data = {};

  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.error || "Request failed (" + response.status + ")"
    );
  }

  return data;
}

function toast(message) {

  const element = $("toast");

  element.textContent = message;

  element.classList.add("show");

  clearTimeout(window.toastTimer);

  window.toastTimer = setTimeout(function () {
    element.classList.remove("show");
  }, 2500);
}

function openAuth(mode) {

  state.authMode = mode || "login";

  renderAuth();

  $("authDialog").showModal();
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

function openNewPoem() {

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

function openEditPoem(id, title, body) {

  state.editingId = id;

  $("poemHeading").textContent = "Edit poem";

  $("poemSubmit").textContent = "Save changes";

  $("poemTitle").value = title;

  $("poemBody").value = body;

  $("poemError").textContent = "";

  $("poemDialog").showModal();
}

async function loadPoems() {

  const data = await api("/api/poems");

  const feed = $("feed");

  if (!data.poems || data.poems.length === 0) {

    feed.innerHTML = `
      <div class="empty">
        No poems yet.<br><br>
        Be the first person to leave a few words here.
      </div>
    `;

    return;
  }

  feed.innerHTML = data.poems.map(function (poem) {

    const canModify =
      state.user &&
      (
        state.user.is_admin ||
        Number(state.user.id) === Number(poem.user_id)
      );

    let actions = "";

    if (canModify) {

      actions = `
        <div class="actions">

          <button
            class="secondary edit-button"
            data-id="${poem.id}"
          >
            Edit
          </button>

          <button
            class="danger delete-button"
            data-id="${poem.id}"
          >
            Delete
          </button>

        </div>
      `;
    }

    return `
      <article class="poem">

        <h3 class="poemTitle">
          ${escapeText(poem.title)}
        </h3>

        <div class="meta">
          by @${escapeText(poem.username)}
          ·
          ${escapeText(
            poem.updated_at ||
            poem.created_at ||
            ""
          )}
        </div>

        <div class="poemBody">
          ${escapeText(poem.body)}
        </div>

        ${actions}

      </article>
    `;

  }).join("");

  document
    .querySelectorAll(".edit-button")
    .forEach(function (button) {

      button.addEventListener("click", async function () {

        try {

          const data = await api(
            "/api/poems/" + button.dataset.id
          );

          openEditPoem(
            data.poem.id,
            data.poem.title,
            data.poem.body
          );

        } catch (error) {

          toast(error.message);
        }
      });
    });

  document
    .querySelectorAll(".delete-button")
    .forEach(function (button) {

      button.addEventListener("click", async function () {

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

/* AUTH BUTTON */

$("authButton").addEventListener(
  "click",
  async function () {

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

      await refreshUser();

      await loadPoems();

      toast("Logged out.");

    } catch (error) {

      toast(error.message);
    }
  }
);

/* NEW POEM */

$("newButton").addEventListener(
  "click",
  openNewPoem
);

/* CLOSE AUTH */

$("authCancel").addEventListener(
  "click",
  function () {
    $("authDialog").close();
  }
);

/* CLOSE POEM */

$("poemCancel").addEventListener(
  "click",
  function () {
    $("poemDialog").close();
  }
);

/* SWITCH LOGIN / REGISTER */

$("switchAuth").addEventListener(
  "click",
  function () {

    state.authMode =
      state.authMode === "login"
        ? "register"
        : "login";

    renderAuth();
  }
);

/* LOGIN / REGISTER */

$("authForm").addEventListener(
  "submit",
  async function (event) {

    event.preventDefault();

    $("authError").textContent = "";

    try {

      await api(
        "/api/" + state.authMode,
        {
          method: "POST",

          body: JSON.stringify({
            username: $("username").value.trim(),
            password: $("password").value
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

/* CREATE / EDIT POEM */

$("poemForm").addEventListener(
  "submit",
  async function (event) {

    event.preventDefault();

    $("poemError").textContent = "";

    const payload = {
      title: $("poemTitle").value.trim(),
      body: $("poemBody").value
    };

    try {

      if (state.editingId) {

        await api(
          "/api/poems/" + state.editingId,
          {
            method: "PUT",
            body: JSON.stringify(payload)
          }
        );

        toast("Poem updated.");

      } else {

        await api(
          "/api/poems",
          {
            method: "POST",
            body: JSON.stringify(payload)
          }
        );

        toast("Poem published.");
      }

      $("poemDialog").close();

      state.editingId = null;

      $("poemForm").reset();

      await loadPoems();

    } catch (error) {

      $("poemError").textContent =
        error.message;
    }
  }
);

/* START */

(async function () {

  try {

    await refreshUser();

    await loadPoems();

  } catch (error) {

    console.error(error);

    $("feed").innerHTML = `
      <div class="empty">
        The site could not load its data.
        <br><br>
        ${escapeText(error.message)}
      </div>
    `;
  }

})();

</script>

</body>
</html>`;
}

/* =========================
   API
========================= */

export default {

  async fetch(request, env) {

    try {

      await setupDatabase(env);

      const url = new URL(request.url);

      /* HOME */

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {

        return new Response(
          appHTML(),
          {
            headers: {
              "Content-Type":
                "text/html; charset=UTF-8",
              "Cache-Control": "no-store"
            }
          }
        );
      }

      /* CURRENT USER */

      if (
        request.method === "GET" &&
        url.pathname === "/api/me"
      ) {

        return json({
          user: await getUser(request, env)
        });
      }

      /* REGISTER */

      if (
        request.method === "POST" &&
        url.pathname === "/api/register"
      ) {

        let body;

        try {
          body = await request.json();
        } catch (error) {
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

        const existing =
          await env.DB.prepare(
            `
            SELECT id
            FROM users
            WHERE username = ?
            COLLATE NOCASE
            `
          )
          .bind(username)
          .first();

        if (existing) {

          return json(
            {
              error:
                "That username is already taken."
            },
            409
          );
        }

        const count =
          await env.DB.prepare(
            "SELECT COUNT(*) AS count FROM users"
          )
          .first();

        const firstUser =
          Number(count?.count || 0) === 0;

        const passwordHash =
          await hashPassword(password);

        const result =
          await env.DB.prepare(
            `
            INSERT INTO users
            (username, password_hash, is_admin)
            VALUES (?, ?, ?)
            `
          )
          .bind(
            username,
            passwordHash,
            firstUser ? 1 : 0
          )
          .run();

        const userId =
          result.meta.last_row_id;

        const session =
          await createSession(
            userId,
            env
          );

        return json(
          {
            ok: true,

            user: {
              id: userId,
              username: username,
              is_admin: firstUser
            }
          },
          200,
          {
            "Set-Cookie":
              makeCookie(session)
          }
        );
      }

      /* LOGIN */

      if (
        request.method === "POST" &&
        url.pathname === "/api/login"
      ) {

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            { error: "Invalid request." },
            400
          );
        }

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        const user =
          await env.DB.prepare(
            `
            SELECT *
            FROM users
            WHERE username = ?
            COLLATE NOCASE
            `
          )
          .bind(username)
          .first();

        if (!user) {

          return json(
            {
              error:
                "Incorrect username or password."
            },
            401
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash
          );

        if (!valid) {

          return json(
            {
              error:
                "Incorrect username or password."
            },
            401
          );
        }

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
              username: user.username,
              is_admin: Boolean(user.is_admin)
            }
          },
          200,
          {
            "Set-Cookie":
              makeCookie(session)
          }
        );
      }

      /* LOGOUT */

      if (
        request.method === "POST" &&
        url.pathname === "/api/logout"
      ) {

        await deleteSession(
          request,
          env
        );

        return json(
          { ok: true },
          200,
          {
            "Set-Cookie":
              makeCookie("", 0)
          }
        );
      }

      /* GET POEMS */

      if (
        request.method === "GET" &&
        url.pathname === "/api/poems"
      ) {

        const result =
          await env.DB.prepare(
            `
            SELECT
              p.id,
              p.user_id,
              p.title,
              p.body,
              p.created_at,
              p.updated_at,
              u.username
            FROM poems p
            JOIN users u
              ON u.id = p.user_id
            ORDER BY
              p.updated_at DESC,
              p.id DESC
            `
          )
          .all();

        return json({
          poems: result.results || []
        });
      }

      /* CREATE POEM */

      if (
        request.method === "POST" &&
        url.pathname === "/api/poems"
      ) {

        const user =
          await getUser(
            request,
            env
          );

        if (!user) {

          return json(
            {
              error:
                "You must be logged in."
            },
            401
          );
        }

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            {
              error:
                "Invalid request."
            },
            400
          );
        }

        const title =
          String(body.title || "").trim();

        const poemBody =
          String(body.body || "");

        if (
          !title ||
          !poemBody.trim()
        ) {

          return json(
            {
              error:
                "Title and poem text are required."
            },
            400
          );
        }

        if (
          title.length > 120 ||
          poemBody.length > 20000
        ) {

          return json(
            {
              error:
                "Poem is too long."
            },
            400
          );
        }

        await env.DB.prepare(
          `
          INSERT INTO poems
          (user_id, title, body)
          VALUES (?, ?, ?)
          `
        )
        .bind(
          user.id,
          title,
          poemBody
        )
        .run();

        return json({
          ok: true
        });
      }

      /* SINGLE POEM */

      const match =
        url.pathname.match(
          /^\/api\/poems\/([0-9]+)$/
        );

      if (
        match &&
        request.method === "GET"
      ) {

        const poemId =
          Number(match[1]);

        const poem =
          await env.DB.prepare(
            `
            SELECT
              p.id,
              p.user_id,
              p.title,
              p.body,
              p.created_at,
              p.updated_at,
              u.username
            FROM poems p
            JOIN users u
              ON u.id = p.user_id
            WHERE p.id = ?
            `
          )
          .bind(poemId)
          .first();

        if (!poem) {

          return json(
            {
              error:
                "Poem not found."
            },
            404
          );
        }

        return json({
          poem: poem
        });
      }

      /* EDIT / DELETE */

      if (
        match &&
        (
          request.method === "PUT" ||
          request.method === "DELETE"
        )
      ) {

        const user =
          await getUser(
            request,
            env
          );

        if (!user) {

          return json(
            {
              error:
                "You must be logged in."
            },
            401
          );
        }

        const poemId =
          Number(match[1]);

        const poem =
          await env.DB.prepare(
            `
            SELECT *
            FROM poems
            WHERE id = ?
            `
          )
          .bind(poemId)
          .first();

        if (!poem) {

          return json(
            {
              error:
                "Poem not found."
            },
            404
          );
        }

        if (
          !user.is_admin &&
          Number(poem.user_id) !==
            Number(user.id)
        ) {

          return json(
            {
              error:
                "You can only modify your own poems."
            },
            403
          );
        }

        /* DELETE */

        if (
          request.method === "DELETE"
        ) {

          await env.DB.prepare(
            `
            DELETE FROM poems
            WHERE id = ?
            `
          )
          .bind(poemId)
          .run();

          return json({
            ok: true
          });
        }

        /* EDIT */

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            {
              error:
                "Invalid request."
            },
            400
          );
        }

        const title =
          String(body.title || "").trim();

        const poemBody =
          String(body.body || "");

        if (
          !title ||
          !poemBody.trim()
        ) {

          return json(
            {
              error:
                "Title and poem text are required."
            },
            400
          );
        }

        if (
          title.length > 120 ||
          poemBody.length > 20000
        ) {

          return json(
            {
              error:
                "Poem is too long."
            },
            400
          );
        }

        await env.DB.prepare(
          `
          UPDATE poems
          SET
            title = ?,
            body = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
          `
        )
        .bind(
          title,
          poemBody,
          poemId
        )
        .run();

        return json({
          ok: true
        });
      }

      return new Response(
        "Not found",
        {
          status: 404
        }
      );

    } catch (error) {

      console.error(
        "SERVER ERROR:",
        error
      );

      return json(
        {
          error:
            error.message ||
            "Server error."
        },
        500
      );
    }
  }
};
