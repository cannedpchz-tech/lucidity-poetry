const COOKIE_NAME = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
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

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);

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

  const parts = stored.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const result = await hashPassword(password, parts[0]);

  return result === stored;
}

function getCookie(request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const part = cookie.trim();

    if (part.startsWith(COOKIE_NAME + "=")) {
      return decodeURIComponent(
        part.substring(COOKIE_NAME.length + 1)
      );
    }
  }

  return null;
}

function makeCookie(token, maxAge = SESSION_SECONDS) {
  return (
    COOKIE_NAME +
    "=" +
    encodeURIComponent(token) +
    "; Max-Age=" +
    maxAge +
    "; Path=/; HttpOnly; Secure; SameSite=Lax"
  );
}

/* =========================================================
   DATABASE
   ========================================================= */

async function setupDatabase(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS lucidity_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS lucidity_poems (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES lucidity_users(id)
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS lucidity_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES lucidity_users(id)
    )
  `).run();
}

async function getCurrentUser(request, env) {
  const token = getCookie(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const result = await env.DB.prepare(`
    SELECT
      u.id,
      u.username,
      u.is_admin
    FROM lucidity_sessions s
    JOIN lucidity_users u
      ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
  `)
    .bind(
      tokenHash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!result) {
    return null;
  }

  return {
    id: result.id,
    username: result.username,
    is_admin: Boolean(result.is_admin)
  };
}

async function createSession(userId, env) {
  const token = randomToken();
  const tokenHash = await sha256(token);

  const expires =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  await env.DB.prepare(`
    DELETE FROM lucidity_sessions
    WHERE user_id = ?
       OR expires_at <= ?
  `)
    .bind(
      userId,
      Math.floor(Date.now() / 1000)
    )
    .run();

  await env.DB.prepare(`
    INSERT INTO lucidity_sessions
      (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(
      tokenHash,
      userId,
      expires
    )
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
    DELETE FROM lucidity_sessions
    WHERE token_hash = ?
  `)
    .bind(tokenHash)
    .run();
}

/* =========================================================
   WEBSITE
   ========================================================= */

function websiteHTML() {
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
  --card: #fffdf8;
  --ink: #1b1917;
  --muted: #756f66;
  --line: #d8d0c3;
  --accent: #70518f;
  --danger: #a33d3d;
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
  border: 1px solid var(--ink);
  background: var(--ink);
  color: white;
  border-radius: 999px;
  padding: 10px 17px;
  cursor: pointer;
  font-family: Arial, sans-serif;
  font-size: 13px;
  font-weight: bold;
}

button.secondary {
  background: transparent;
  color: var(--ink);
  border-color: var(--line);
}

button.danger {
  background: transparent;
  color: var(--danger);
  border-color: #d6aaa5;
}

.site {
  width: min(1100px, calc(100% - 30px));
  margin: auto;
}

header {
  position: sticky;
  top: 0;
  z-index: 10;
  background: rgba(244, 239, 230, 0.95);
  border-bottom: 1px solid var(--line);
}

.nav {
  height: 70px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.brand {
  font-size: 24px;
  font-weight: bold;
}

.brand small {
  display: block;
  color: var(--muted);
  font-family: Arial, sans-serif;
  font-size: 9px;
  letter-spacing: 3px;
  text-transform: uppercase;
}

.navRight {
  display: flex;
  align-items: center;
  gap: 10px;
}

#who {
  color: var(--muted);
  font: 12px Arial, sans-serif;
}

.hero {
  padding: 75px 0 60px;
  display: grid;
  grid-template-columns: 1.3fr 0.7fr;
  gap: 50px;
  align-items: end;
}

.eyebrow {
  color: var(--accent);
  font: bold 11px Arial, sans-serif;
  letter-spacing: 3px;
  text-transform: uppercase;
  margin-bottom: 18px;
}

.hero h1 {
  font-size: clamp(50px, 8vw, 90px);
  line-height: 0.9;
  letter-spacing: -4px;
  font-weight: normal;
  margin: 0;
}

.hero p {
  color: var(--muted);
  font-size: 20px;
  line-height: 1.6;
}

.credit {
  color: var(--muted);
  font: 12px Arial, sans-serif;
  margin-top: 20px;
}

.rule {
  height: 1px;
  background: var(--line);
}

.toolbar {
  padding: 24px 0 18px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.toolbar h2 {
  margin: 0;
  font-size: 21px;
  font-weight: normal;
}

.feed {
  padding-bottom: 90px;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
}

.poem {
  background: var(--card);
  border: 1px solid var(--line);
  padding: 28px;
  min-height: 260px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 14px 45px rgba(35, 28, 18, 0.07);
}

.poemTitle {
  margin: 0 0 8px;
  font-size: 29px;
  font-weight: normal;
  line-height: 1.1;
}

.meta {
  color: var(--muted);
  font: 12px Arial, sans-serif;
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
  padding: 70px 20px;
  text-align: center;
  color: var(--muted);
  border: 1px dashed var(--line);
}

dialog {
  width: min(580px, calc(100% - 25px));
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 0;
  background: var(--card);
  color: var(--ink);
}

dialog::backdrop {
  background: rgba(20, 16, 12, 0.55);
}

.modal {
  padding: 30px;
}

.modal h2 {
  margin: 0 0 5px;
  font-size: 34px;
  font-weight: normal;
}

.sub {
  color: var(--muted);
  font: 13px Arial, sans-serif;
  margin-bottom: 20px;
}

label {
  display: block;
  margin: 15px 0 7px;
  color: var(--muted);
  font: bold 11px Arial, sans-serif;
  letter-spacing: 1px;
  text-transform: uppercase;
}

input,
textarea {
  width: 100%;
  border: 1px solid var(--line);
  background: white;
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
  color: var(--danger);
  min-height: 20px;
  margin-top: 10px;
  font: 13px Arial, sans-serif;
}

.switch {
  color: var(--muted);
  text-align: center;
  margin-top: 18px;
  font: 13px Arial, sans-serif;
}

.switch a {
  color: var(--accent);
  font-weight: bold;
  cursor: pointer;
}

.toast {
  position: fixed;
  left: 50%;
  bottom: 25px;
  transform: translateX(-50%);
  background: var(--ink);
  color: white;
  padding: 12px 18px;
  border-radius: 999px;
  font: 13px Arial, sans-serif;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s;
  z-index: 100;
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

  #who {
    display: none;
  }
}
</style>
</head>

<body>

<header>
  <nav class="site nav">
    <div class="brand">
      Lucidity
      <small>Poetry Archive</small>
    </div>

    <div class="navRight">
      <span id="who"></span>
      <button id="authButton" class="secondary">Log in</button>
    </div>
  </nav>
</header>

<main class="site">

<section class="hero">
  <div>
    <div class="eyebrow">A place for words</div>

    <h1>Write what<br>you cannot say.</h1>

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

<dialog id="authDialog">
  <div class="modal">

    <h2 id="authHeading">Log in</h2>

    <div id="authSub" class="sub">
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
      <span id="switchLabel">New here?</span>
      <a id="switchAuth">Create an account</a>
    </div>

  </div>
</dialog>

<dialog id="poemDialog">
  <div class="modal">

    <h2 id="poemHeading">Write a poem</h2>

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
(function () {

  var state = {
    user: null,
    editingId: null,
    authMode: "login"
  };

  function $(id) {
    return document.getElementById(id);
  }

  function escapeText(value) {
    return String(value == null ? "" : value)
      .replace(/[&<>"']/g, function (char) {
        var map = {
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;"
        };

        return map[char];
      });
  }

  async function api(url, options) {

    options = options || {};

    var headers = options.headers || {};

    headers["Content-Type"] = "application/json";

    var response = await fetch(
      url,
      Object.assign({}, options, {
        headers: headers
      })
    );

    var data = {};

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

  function showToast(message) {
    var toast = $("toast");

    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(window.toastTimer);

    window.toastTimer = setTimeout(function () {
      toast.classList.remove("show");
    }, 2500);
  }

  function openAuth(mode) {

    state.authMode = mode || "login";

    renderAuth();

    $("authDialog").showModal();
  }

  function renderAuth() {

    var register = state.authMode === "register";

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

    var data = await api("/api/me");

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

    var data = await api("/api/poems");

    var feed = $("feed");

    if (!data.poems || data.poems.length === 0) {

      feed.innerHTML =
        '<div class="empty">' +
        'No poems yet.<br><br>' +
        'Be the first person to leave a few words here.' +
        '</div>';

      return;
    }

    feed.innerHTML = data.poems.map(function (poem) {

      var canEdit =
        state.user &&
        (
          state.user.is_admin ||
          Number(state.user.id) === Number(poem.user_id)
        );

      var actions = "";

      if (canEdit) {

        actions =
          '<div class="actions">' +

          '<button ' +
          'class="secondary edit" ' +
          'data-id="' + poem.id + '" ' +
          'data-title="' +
          encodeURIComponent(poem.title) +
          '" ' +
          'data-body="' +
          encodeURIComponent(poem.body) +
          '">' +
          'Edit' +
          '</button>' +

          '<button ' +
          'class="danger delete" ' +
          'data-id="' + poem.id + '">' +
          'Delete' +
          '</button>' +

          '</div>';
      }

      return (
        '<article class="poem">' +

        '<h3 class="poemTitle">' +
        escapeText(poem.title) +
        '</h3>' +

        '<div class="meta">' +
        'by @' +
        escapeText(poem.username) +
        ' · ' +
        escapeText(
          poem.updated_at ||
          poem.created_at ||
          ""
        ) +
        '</div>' +

        '<div class="poemBody">' +
        escapeText(poem.body) +
        '</div>' +

        actions +

        '</article>'
      );

    }).join("");

    Array.from(
      feed.querySelectorAll(".edit")
    ).forEach(function (button) {

      button.addEventListener(
        "click",
        function () {

          openEditPoem(
            Number(button.dataset.id),
            decodeURIComponent(
              button.dataset.title
            ),
            decodeURIComponent(
              button.dataset.body
            )
          );

        }
      );

    });

    Array.from(
      feed.querySelectorAll(".delete")
    ).forEach(function (button) {

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
              "/api/poems/" + button.dataset.id,
              {
                method: "DELETE"
              }
            );

            showToast("Poem deleted.");

            await loadPoems();

          } catch (error) {

            showToast(error.message);
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

        await refreshUser();
        await loadPoems();

        showToast("Logged out.");

      } catch (error) {

        showToast(error.message);
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

        showToast(
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

      var payload = {
        title: $("poemTitle").value.trim(),
        body: $("poemBody").value
      };

      try {

        if (state.editingId) {

          await api(
            "/api/poems/" +
            state.editingId,
            {
              method: "PUT",
              body: JSON.stringify(payload)
            }
          );

        } else {

          await api(
            "/api/poems",
            {
              method: "POST",
              body: JSON.stringify(payload)
            }
          );
        }

        var wasEditing =
          Boolean(state.editingId);

        $("poemDialog").close();

        state.editingId = null;

        await loadPoems();

        showToast(
          wasEditing
            ? "Poem updated."
            : "Poem published."
        );

      } catch (error) {

        $("poemError").textContent =
          error.message;
      }
    }
  );

  (async function () {

    try {

      await refreshUser();
      await loadPoems();

    } catch (error) {

      console.error(error);

      $("feed").innerHTML =
        '<div class="empty">' +
        'The site could not load its data.<br><br>' +
        escapeText(error.message) +
        '</div>';
    }

  })();

})();
</script>

</body>
</html>`;
}

/* =========================================================
   API
   ========================================================= */

export default {

  async fetch(request, env) {

    const url = new URL(request.url);

    try {

      await setupDatabase(env);

      /* HOME */

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {

        return new Response(
          websiteHTML(),
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
          user: await getCurrentUser(
            request,
            env
          )
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
          await env.DB.prepare(`
            SELECT id
            FROM lucidity_users
            WHERE username = ? COLLATE NOCASE
          `)
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
          await env.DB.prepare(`
            SELECT COUNT(*) AS count
            FROM lucidity_users
          `)
            .first();

        const isFirstUser =
          Number(count.count) === 0;

        const passwordHash =
          await hashPassword(password);

        const result =
          await env.DB.prepare(`
            INSERT INTO lucidity_users
              (username, password_hash, is_admin)
            VALUES (?, ?, ?)
          `)
            .bind(
              username,
              passwordHash,
              isFirstUser ? 1 : 0
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
              is_admin: isFirstUser
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
          await env.DB.prepare(`
            SELECT *
            FROM lucidity_users
            WHERE username = ? COLLATE NOCASE
          `)
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
              is_admin: Boolean(
                user.is_admin
              )
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
          await env.DB.prepare(`
            SELECT
              p.id,
              p.user_id,
              p.title,
              p.body,
              p.created_at,
              p.updated_at,
              u.username
            FROM lucidity_poems p
            JOIN lucidity_users u
              ON u.id = p.user_id
            ORDER BY
              p.updated_at DESC,
              p.id DESC
          `)
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
          await getCurrentUser(
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

        const poem =
          String(body.body || "");

        if (!title || !poem.trim()) {

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
          poem.length > 20000
        ) {

          return json(
            {
              error:
                "The poem is too long."
            },
            400
          );
        }

        await env.DB.prepare(`
          INSERT INTO lucidity_poems
            (user_id, title, body)
          VALUES (?, ?, ?)
        `)
          .bind(
            user.id,
            title,
            poem
          )
          .run();

        return json({
          ok: true
        });
      }

      /* EDIT / DELETE POEM */

      const poemMatch =
        url.pathname.match(
          /^\\/api\\/poems\\/([0-9]+)$/
        );

      if (
        poemMatch &&
        (
          request.method === "PUT" ||
          request.method === "DELETE"
        )
      ) {

        const user =
          await getCurrentUser(
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
          Number(poemMatch[1]);

        const poem =
          await env.DB.prepare(`
            SELECT *
            FROM lucidity_poems
            WHERE id = ?
          `)
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

        const allowed =
          user.is_admin ||
          Number(user.id) ===
          Number(poem.user_id);

        if (!allowed) {

          return json(
            {
              error:
                "You can only modify your own poems."
            },
            403
          );
        }

        if (request.method === "DELETE") {

          await env.DB.prepare(`
            DELETE FROM lucidity_poems
            WHERE id = ?
          `)
            .bind(poemId)
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

        const text =
          String(body.body || "");

        if (!title || !text.trim()) {

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
          text.length > 20000
        ) {

          return json(
            {
              error:
                "The poem is too long."
            },
            400
          );
        }

        await env.DB.prepare(`
          UPDATE lucidity_poems
          SET
            title = ?,
            body = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(
            title,
            text,
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
        "LUCIDITY ERROR:",
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
