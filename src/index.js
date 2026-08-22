const encoder = new TextEncoder();

const COOKIE = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, function (c) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c];
  });
}

function randomHex(bytes) {
  const array = new Uint8Array(bytes || 32);
  crypto.getRandomValues(array);

  return Array.from(array)
    .map(function (x) {
      return x.toString(16).padStart(2, "0");
    })
    .join("");
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(result))
    .map(function (x) {
      return x.toString(16).padStart(2, "0");
    })
    .join("");
}

async function hashPassword(password, saltHex) {
  let salt;

  if (saltHex) {
    const pieces = saltHex.match(/../g) || [];

    salt = new Uint8Array(
      pieces.map(function (x) {
        return parseInt(x, 16);
      })
    );
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16));
  }

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
      salt: salt,
      iterations: 150000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const saltString = Array.from(salt)
    .map(function (x) {
      return x.toString(16).padStart(2, "0");
    })
    .join("");

  const hashString = Array.from(new Uint8Array(bits))
    .map(function (x) {
      return x.toString(16).padStart(2, "0");
    })
    .join("");

  return saltString + ":" + hashString;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) {
    return false;
  }

  const parts = stored.split(":");
  const salt = parts[0];
  const hash = parts[1];

  const calculated = await hashPassword(password, salt);

  return calculated === salt + ":" + hash;
}

function getCookie(request) {
  const header = request.headers.get("Cookie") || "";

  const cookies = header.split(";");

  for (const item of cookies) {
    const trimmed = item.trim();

    if (trimmed.startsWith(COOKIE + "=")) {
      return decodeURIComponent(
        trimmed.substring(COOKIE.length + 1)
      );
    }
  }

  return null;
}

function makeCookie(token, maxAge) {
  return (
    COOKIE +
    "=" +
    encodeURIComponent(token) +
    "; Max-Age=" +
    maxAge +
    "; Path=/; HttpOnly; Secure; SameSite=Lax"
  );
}

async function ensureSessionsTable(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS sessions (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT," +
      "token_hash TEXT NOT NULL UNIQUE," +
      "user_id INTEGER NOT NULL," +
      "expires_at INTEGER NOT NULL" +
    ")"
  ).run();

  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_sessions_token " +
    "ON sessions(token_hash)"
  ).run();
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token) {
    return null;
  }

  await ensureSessionsTable(env);

  const hash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const user = await env.DB.prepare(
    "SELECT u.id, u.username, u.is_admin " +
    "FROM sessions s " +
    "JOIN users u ON u.id = s.user_id " +
    "WHERE s.token_hash = ? AND s.expires_at > ?"
  )
    .bind(hash, now)
    .first();

  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    is_admin: Boolean(user.is_admin)
  };
}

async function createSession(userId, env) {
  await ensureSessionsTable(env);

  const token = randomHex(32);
  const hash = await sha256(token);
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  await env.DB.prepare(
    "DELETE FROM sessions WHERE user_id = ?"
  )
    .bind(userId)
    .run();

  await env.DB.prepare(
    "INSERT INTO sessions(token_hash, user_id, expires_at) " +
    "VALUES (?, ?, ?)"
  )
    .bind(hash, userId, expires)
    .run();

  return token;
}

async function deleteSession(request, env) {
  const token = getCookie(request);

  if (!token) {
    return;
  }

  await ensureSessionsTable(env);

  const hash = await sha256(token);

  await env.DB.prepare(
    "DELETE FROM sessions WHERE token_hash = ?"
  )
    .bind(hash)
    .run();
}

async function requireUser(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return null;
  }

  return user;
}

function appHTML() {
  return `<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Lucidity — Poetry by Juan Pablo F.</title>

<style>

:root {
  --paper: #f4efe6;
  --ink: #1b1a18;
  --muted: #746f66;
  --line: #d8d0c3;
  --card: #fbf8f1;
  --accent: #6e4e8f;
  --danger: #9d3d3d;
  --shadow: 0 14px 45px rgba(35,28,18,.08);
}

* {
  box-sizing: border-box;
}

html {
  scroll-behavior: smooth;
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
}

.site {
  max-width: 1120px;
  margin: auto;
  padding: 0 22px;
}

.top {
  border-bottom: 1px solid var(--line);
  background: rgba(244,239,230,.94);
  backdrop-filter: blur(12px);
  position: sticky;
  top: 0;
  z-index: 10;
}

.nav {
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
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
  color: var(--muted);
  font: 600 12px system-ui, sans-serif;
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
  margin-top: 20px;
  color: var(--muted);
  font: 12px system-ui, sans-serif;
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

.buttons {
  display: flex;
  gap: 9px;
}

button {
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

.feed {
  display: grid;
  grid-template-columns: repeat(2, minmax(0,1fr));
  gap: 18px;
  padding-bottom: 90px;
}

.poem {
  background: var(--card);
  border: 1px solid var(--line);
  padding: 28px;
  box-shadow: var(--shadow);
  min-height: 260px;
  display: flex;
  flex-direction: column;
}

.poem.admin {
  border-top: 3px solid var(--accent);
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

.loading {
  color: var(--muted);
  font: 13px system-ui, sans-serif;
}

dialog {
  width: min(580px, calc(100% - 28px));
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--ink);
  padding: 0;
  border-radius: 4px;
  box-shadow: 0 30px 100px rgba(0,0,0,.25);
}

dialog::backdrop {
  background: rgba(25,20,15,.5);
  backdrop-filter: blur(3px);
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
  min-height: 260px;
  resize: vertical;
  line-height: 1.7;
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
  font-weight: 700;
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
  pointer-events: none;
  transition: .2s;
  z-index: 50;
}

.toast.show {
  opacity: 1;
}

@media (max-width: 760px) {

  .hero {
    grid-template-columns: 1fr;
    gap: 24px;
    padding: 55px 0 45px;
  }

  .feed {
    grid-template-columns: 1fr;
  }

  .pill {
    display: none;
  }

  .site {
    padding: 0 15px;
  }

  .poem {
    padding: 23px;
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

<button
class="secondary"
id="authButton"
type="button"
>
Log in
</button>

</div>

</nav>

</header>

<main class="site">

<section class="hero">

<div>

<div class="eyebrow">
A place for words
</div>

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

<button
id="newButton"
type="button"
>
Write a poem
</button>

</div>

</section>

<section
id="feed"
class="feed"
>

<div class="loading">
Loading poems...
</div>

</section>

</main>

<div id="toast" class="toast"></div>

<dialog id="authDialog">

<div class="modal">

<h2 id="authHeading">
Log in
</h2>

<div
class="sub"
id="authSub"
>
Return to your writing.
</div>

<form id="authForm">

<label>
Username
</label>

<input
id="username"
autocomplete="username"
required
minlength="3"
maxlength="30"
>

<label>
Password
</label>

<input
id="password"
type="password"
autocomplete="current-password"
required
minlength="8"
>

<div
id="authError"
class="error"
></div>

<div class="formActions">

<button
type="button"
class="secondary"
id="authCancel"
>
Cancel
</button>

<button
type="submit"
id="authSubmit"
>
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

<dialog id="poemDialog">

<div class="modal">

<h2 id="poemHeading">
Write a poem
</h2>

<div class="sub">
Put it here. You can change or remove it later.
</div>

<form id="poemForm">

<label>
Title
</label>

<input
id="poemTitle"
maxlength="120"
required
>

<label>
Your poem
</label>

<textarea
id="poemBody"
maxlength="20000"
required
></textarea>

<div
id="poemError"
class="error"
></div>

<div class="formActions">

<button
type="button"
class="secondary"
id="poemCancel"
>
Cancel
</button>

<button
type="submit"
id="poemSubmit"
>
Publish poem
</button>

</div>

</form>

</div>

</dialog>

<script>

(function () {

"use strict";

const state = {
  user: null,
  editingId: null,
  authMode: "login"
};

function $(id) {
  return document.getElementById(id);
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, function (c) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c];
  });
}

async function api(url, options) {

  const opts = options || {};

  const headers = {
    "content-type": "application/json"
  };

  if (opts.headers) {
    Object.assign(headers, opts.headers);
  }

  const response = await fetch(url, {
    ...opts,
    headers: headers
  });

  let data = {};

  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }

  if (!response.ok) {
    throw new Error(
      data.error ||
      ("Request failed (" + response.status + ")")
    );
  }

  return data;
}

function toast(message) {

  const element = $("toast");

  element.textContent = message;
  element.classList.add("show");

  clearTimeout(toast.timer);

  toast.timer = setTimeout(function () {
    element.classList.remove("show");
  }, 2500);
}

function openAuth(mode) {

  state.authMode = mode || "login";

  renderAuth();

  $("authDialog").showModal();

  setTimeout(function () {
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

  if (!data.poems || data.poems.length === 0) {

    feed.innerHTML =
      '<div class="empty">' +
      "No poems yet.<br><br>" +
      "Be the first person to leave a few words here." +
      "</div>";

    return;
  }

  feed.innerHTML = data.poems.map(function (poem) {

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

    let actions = "";

    if (canModify) {

      actions =
        '<div class="actions">' +

        '<button ' +
        'type="button" ' +
        'class="secondary edit" ' +
        'data-id="' + poem.id + '">' +
        "Edit" +
        "</button>" +

        '<button ' +
        'type="button" ' +
        'class="danger delete" ' +
        'data-id="' + poem.id + '">' +
        "Delete" +
        "</button>" +

        "</div>";
    }

    return (
      '<article class="poem ' +
      adminClass +
      '">' +

      '<h3 class="poemTitle">' +
      escapeHTML(poem.title) +
      "</h3>" +

      '<div class="meta">' +
      "by @" +
      escapeHTML(poem.username) +
      " · " +
      escapeHTML(
        poem.updated_at ||
        poem.created_at ||
        ""
      ) +
      "</div>" +

      '<div class="poemBody">' +
      escapeHTML(poem.body) +
      "</div>" +

      actions +

      "</article>"
    );

  }).join("");

  feed
    .querySelectorAll(".edit")
    .forEach(function (button) {

      button.addEventListener(
        "click",
        async function () {

          const id = Number(button.dataset.id);

          const data = await api(
            "/api/poems/" + id
          );

          if (data.poem) {

            openEdit(
              data.poem.id,
              data.poem.title,
              data.poem.body
            );

          }

        }
      );

    });

  feed
    .querySelectorAll(".delete")
    .forEach(function (button) {

      button.addEventListener(
        "click",
        async function () {

          if (
            !confirm(
              "Delete this poem? This cannot be undone."
            )
          ) {
            return;
          }

          try {

            await api(
              "/api/poems/" +
              button.dataset.id,
              {
                method: "DELETE"
              }
            );

            toast("Poem deleted.");

            await loadPoems();

          } catch (error) {

            toast(error.message);
          }

        }
      );

    });
}

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
  openNewPoem
);

$("authCancel").addEventListener(
  "click",
  function () {
    $("authDialog").close();
  }
);

$("poemCancel").addEventListener(
  "click",
  function () {
    $("poemDialog").close();
  }
);

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

$("authForm").addEventListener(
  "submit",
  async function (event) {

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
            username: username,
            password: password
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
  async function (event) {

    event.preventDefault();

    $("poemError").textContent = "";

    const title =
      $("poemTitle").value.trim();

    const body =
      $("poemBody").value;

    try {

      if (state.editingId) {

        await api(
          "/api/poems/" +
          state.editingId,
          {
            method: "PUT",
            body: JSON.stringify({
              title: title,
              body: body
            })
          }
        );

        toast("Poem updated.");

      } else {

        await api(
          "/api/poems",
          {
            method: "POST",
            body: JSON.stringify({
              title: title,
              body: body
            })
          }
        );

        toast("Poem published.");
      }

      $("poemDialog").close();

      state.editingId = null;

      await loadPoems();

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

    $("feed").innerHTML =
      '<div class="empty">' +
      "The site could not load its data.<br><br>" +
      "<small>" +
      escapeHTML(error.message) +
      "</small>" +
      "</div>";
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

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {

        return new Response(
          appHTML(),
          {
            status: 200,
            headers: {
              "content-type":
                "text/html; charset=UTF-8",
              "cache-control": "no-store"
            }
          }
        );
      }

      if (
        request.method === "GET" &&
        url.pathname === "/api/me"
      ) {

        return json({
          user: await getUser(request, env)
        });
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/register"
      ) {

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            {
              error: "Invalid request."
            },
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
                "Username must be 3-30 characters using letters, numbers, or underscores."
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

        const existing = await env.DB.prepare(
          "SELECT id FROM users " +
          "WHERE username = ? COLLATE NOCASE"
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

        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS count FROM users"
        ).first();

        const isAdmin =
          Number(count.count || 0) === 0;

        const passwordHash =
          await hashPassword(password);

        const result = await env.DB.prepare(
          "INSERT INTO users " +
          "(username, password_hash, is_admin) " +
          "VALUES (?, ?, ?)"
        )
          .bind(
            username,
            passwordHash,
            isAdmin ? 1 : 0
          )
          .run();

        const session =
          await createSession(
            result.meta.last_row_id,
            env
          );

        return json(
          {
            ok: true
          },
          200,
          {
            "set-cookie":
              makeCookie(
                session,
                SESSION_SECONDS
              )
          }
        );
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/login"
      ) {

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            {
              error: "Invalid request."
            },
            400
          );
        }

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        const user = await env.DB.prepare(
          "SELECT id, username, password_hash, is_admin " +
          "FROM users " +
          "WHERE username = ? COLLATE NOCASE"
        )
          .bind(username)
          .first();

        if (
          !user ||
          !(await verifyPassword(
            password,
            user.password_hash
          ))
        ) {

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
            ok: true
          },
          200,
          {
            "set-cookie":
              makeCookie(
                session,
                SESSION_SECONDS
              )
          }
        );
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/logout"
      ) {

        await deleteSession(
          request,
          env
        );

        return json(
          {
            ok: true
          },
          200,
          {
            "set-cookie":
              makeCookie("", 0)
          }
        );
      }

      if (
        request.method === "GET" &&
        url.pathname === "/api/poems"
      ) {

        const result = await env.DB.prepare(
          "SELECT " +
          "p.id, " +
          "p.user_id, " +
          "p.title, " +
          "p.body, " +
          "p.created_at, " +
          "p.updated_at, " +
          "u.username " +
          "FROM poems p " +
          "JOIN users u ON u.id = p.user_id " +
          "ORDER BY p.updated_at DESC, p.id DESC"
        ).all();

        return json({
          poems: result.results || []
        });
      }

      const poemMatch =
        url.pathname.match(
          /^\/api\/poems\/(\d+)$/
        );

      if (
        poemMatch &&
        request.method === "GET"
      ) {

        const id =
          Number(poemMatch[1]);

        const poem =
          await env.DB.prepare(
            "SELECT " +
            "p.id, " +
            "p.user_id, " +
            "p.title, " +
            "p.body, " +
            "p.created_at, " +
            "p.updated_at, " +
            "u.username " +
            "FROM poems p " +
            "JOIN users u ON u.id = p.user_id " +
            "WHERE p.id = ?"
          )
            .bind(id)
            .first();

        if (!poem) {

          return json(
            {
              error: "Poem not found."
            },
            404
          );
        }

        return json({
          poem: poem
        });
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/poems"
      ) {

        const user =
          await requireUser(
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
              error: "Invalid request."
            },
            400
          );
        }

        const title =
          String(body.title || "").trim();

        const poemBody =
          String(body.body || "");

        if (!title || !poemBody.trim()) {

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
          "INSERT INTO poems " +
          "(user_id, title, body) " +
          "VALUES (?, ?, ?)"
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

      if (
        poemMatch &&
        (
          request.method === "PUT" ||
          request.method === "DELETE"
        )
      ) {

        const user =
          await requireUser(
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

        const id =
          Number(poemMatch[1]);

        const poem =
          await env.DB.prepare(
            "SELECT * FROM poems WHERE id = ?"
          )
            .bind(id)
            .first();

        if (!poem) {

          return json(
            {
              error: "Poem not found."
            },
            404
          );
        }

        if (
          !user.is_admin &&
          Number(poem.user_id) !== Number(user.id)
        ) {

          return json(
            {
              error:
                "You can only modify your own poems."
            },
            403
          );
        }

        if (
          request.method === "DELETE"
        ) {

          await env.DB.prepare(
            "DELETE FROM poems WHERE id = ?"
          )
            .bind(id)
            .run();

          return json({
            ok: true
          });
        }

        let body;

        try {
          body = await request.json();
        } catch (error) {
          return json(
            {
              error: "Invalid request."
            },
            400
          );
        }

        const title =
          String(body.title || "").trim();

        const poemBody =
          String(body.body || "");

        if (!title || !poemBody.trim()) {

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
          "UPDATE poems " +
          "SET title = ?, " +
          "body = ?, " +
          "updated_at = CURRENT_TIMESTAMP " +
          "WHERE id = ?"
        )
          .bind(
            title,
            poemBody,
            id
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
