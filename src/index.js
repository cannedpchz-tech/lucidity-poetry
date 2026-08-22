const COOKIE = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extra
    }
  });
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  for (const part of cookies.split(";")) {
    const item = part.trim();

    if (item.startsWith(COOKIE + "=")) {
      return decodeURIComponent(item.slice(COOKIE.length + 1));
    }
  }

  return null;
}

function makeCookie(token, maxAge = SESSION_SECONDS) {
  return `${COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return [...bytes]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function passwordHash(password) {
  return sha256(password);
}

async function setup(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS poems (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `).run();
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const result = await env.DB.prepare(`
    SELECT
      users.id,
      users.username,
      users.is_admin
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `)
    .bind(tokenHash, Math.floor(Date.now() / 1000))
    .first();

  return result || null;
}

async function createSession(userId, env) {
  const token = randomToken();
  const tokenHash = await sha256(token);

  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  await env.DB.prepare(`
    INSERT INTO sessions (
      token_hash,
      user_id,
      expires_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(
      tokenHash,
      userId,
      Math.floor(Date.now() / 1000) + SESSION_SECONDS
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
    DELETE FROM sessions
    WHERE token_hash = ?
  `)
    .bind(tokenHash)
    .run();
}

function page() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Lucidity — Poetry Archive</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #f4efe6;
  color: #1b1a18;
  font-family: Georgia, "Times New Roman", serif;
}

header {
  border-bottom: 1px solid #d8d0c3;
  padding: 20px;
}

nav {
  max-width: 1000px;
  margin: auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.logo {
  font-size: 25px;
  font-weight: bold;
}

button {
  border: none;
  border-radius: 20px;
  padding: 10px 17px;
  background: #1b1a18;
  color: white;
  cursor: pointer;
}

button:hover {
  opacity: .85;
}

main {
  max-width: 1000px;
  margin: auto;
  padding: 60px 20px;
}

.hero h1 {
  font-size: clamp(50px, 9vw, 90px);
  line-height: .9;
  font-weight: 500;
  margin: 0;
}

.hero p {
  color: #746f66;
  font-size: 19px;
  max-width: 500px;
  line-height: 1.6;
}

.divider {
  height: 1px;
  background: #d8d0c3;
  margin: 60px 0 25px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.poems {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
}

.poem {
  background: #fbf8f1;
  border: 1px solid #d8d0c3;
  padding: 25px;
}

.poem h2 {
  font-weight: 500;
}

.poem .body {
  white-space: pre-wrap;
  line-height: 1.8;
}

.meta {
  color: #746f66;
  font: 13px system-ui, sans-serif;
}

.actions {
  margin-top: 20px;
  display: flex;
  gap: 8px;
}

.empty {
  border: 1px dashed #d8d0c3;
  padding: 50px;
  text-align: center;
  color: #746f66;
  grid-column: 1 / -1;
}

dialog {
  border: none;
  width: min(550px, 90%);
  padding: 0;
}

dialog::backdrop {
  background: rgba(0,0,0,.5);
}

.modal {
  padding: 30px;
}

.modal h2 {
  font-size: 30px;
  font-weight: 500;
}

label {
  display: block;
  margin-top: 15px;
  margin-bottom: 6px;
  font-family: system-ui, sans-serif;
  font-size: 12px;
  font-weight: bold;
}

input,
textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #d8d0c3;
}

textarea {
  min-height: 220px;
  resize: vertical;
}

.form-buttons {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.error {
  color: #a33;
  margin-top: 10px;
}

@media (max-width: 700px) {
  .poems {
    grid-template-columns: 1fr;
  }
}

</style>
</head>

<body>

<header>
<nav>
<div class="logo">Lucidity</div>

<div>
<button id="loginButton">Log in</button>
</div>
</nav>
</header>

<main>

<section class="hero">

<h1>
Write what<br>
you cannot say.
</h1>

<p>
A quiet place for poems, thoughts,
and words that deserve somewhere to exist.
</p>

</section>

<div class="divider"></div>

<div class="toolbar">

<h2>Recent poems</h2>

<button id="writeButton">
Write a poem
</button>

</div>

<section id="poems" class="poems">

<div class="empty">
Loading poems...
</div>

</section>

</main>

<dialog id="authDialog">

<div class="modal">

<h2 id="authTitle">
Log in
</h2>

<form id="authForm">

<label>
Username
</label>

<input
id="username"
required
minlength="3"
maxlength="30"
/>

<label>
Password
</label>

<input
id="password"
type="password"
required
minlength="8"
/>

<div id="authError" class="error"></div>

<div class="form-buttons">

<button
type="button"
id="authCancel"
>
Cancel
</button>

<button>
Continue
</button>

</div>

</form>

<p>
<a href="#" id="switchAuth">
Create an account
</a>
</p>

</div>

</dialog>

<dialog id="poemDialog">

<div class="modal">

<h2 id="poemTitle">
Write a poem
</h2>

<form id="poemForm">

<label>
Title
</label>

<input
id="title"
maxlength="120"
required
/>

<label>
Poem
</label>

<textarea
id="body"
maxlength="20000"
required
></textarea>

<div id="poemError" class="error"></div>

<div class="form-buttons">

<button
type="button"
id="poemCancel"
>
Cancel
</button>

<button>
Publish
</button>

</div>

</form>

</div>

</dialog>

<script>

let user = null;
let authMode = "login";
let editingId = null;

const $ = id => document.getElementById(id);

async function api(url, options = {}) {

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  let data = {};

  try {
    data = await response.json();
  } catch {}

  if (!response.ok) {
    throw new Error(
      data.error || "Something went wrong."
    );
  }

  return data;
}

function escapeText(text) {

  const div = document.createElement("div");

  div.textContent = text;

  return div.innerHTML;
}

async function loadUser() {

  const data = await api("/api/me");

  user = data.user;

  if (user) {

    $("loginButton").textContent =
      "Log out";

  } else {

    $("loginButton").textContent =
      "Log in";

  }
}

async function loadPoems() {

  const data = await api("/api/poems");

  const container = $("poems");

  if (!data.poems.length) {

    container.innerHTML =
      '<div class="empty">No poems yet.<br><br>Be the first to write one.</div>';

    return;
  }

  container.innerHTML = "";

  for (const poem of data.poems) {

    const article =
      document.createElement("article");

    article.className = "poem";

    article.innerHTML = `
      <h2>${escapeText(poem.title)}</h2>

      <div class="meta">
        by @${escapeText(poem.username)}
      </div>

      <div class="body">
        ${escapeText(poem.body)}
      </div>
    `;

    if (
      user &&
      (
        user.is_admin ||
        Number(user.id) === Number(poem.user_id)
      )
    ) {

      const actions =
        document.createElement("div");

      actions.className = "actions";

      const edit =
        document.createElement("button");

      edit.textContent = "Edit";

      edit.onclick = () => {
        openEditor(poem);
      };

      const remove =
        document.createElement("button");

      remove.textContent = "Delete";

      remove.onclick = async () => {

        if (!confirm("Delete this poem?")) {
          return;
        }

        try {

          await api(
            "/api/poems/" + poem.id,
            {
              method: "DELETE"
            }
          );

          await loadPoems();

        } catch (error) {

          alert(error.message);

        }
      };

      actions.appendChild(edit);
      actions.appendChild(remove);

      article.appendChild(actions);
    }

    container.appendChild(article);
  }
}

function openAuth(mode) {

  authMode = mode;

  $("authTitle").textContent =
    mode === "login"
      ? "Log in"
      : "Create an account";

  $("switchAuth").textContent =
    mode === "login"
      ? "Create an account"
      : "Log in";

  $("authError").textContent = "";

  $("authDialog").showModal();
}

$("loginButton").onclick = async () => {

  if (!user) {

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

    await loadUser();
    await loadPoems();

  } catch (error) {

    alert(error.message);

  }
};

$("switchAuth").onclick = event => {

  event.preventDefault();

  openAuth(
    authMode === "login"
      ? "register"
      : "login"
  );
};

$("authCancel").onclick = () => {

  $("authDialog").close();

};

$("authForm").onsubmit = async event => {

  event.preventDefault();

  $("authError").textContent = "";

  try {

    await api(
      "/api/" + authMode,
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

    await loadUser();
    await loadPoems();

  } catch (error) {

    $("authError").textContent =
      error.message;

  }
};

$("writeButton").onclick = () => {

  if (!user) {

    openAuth("login");

    return;
  }

  editingId = null;

  $("poemTitle").textContent =
    "Write a poem";

  $("title").value = "";
  $("body").value = "";
  $("poemError").textContent = "";

  $("poemDialog").showModal();
};

function openEditor(poem) {

  editingId = poem.id;

  $("poemTitle").textContent =
    "Edit poem";

  $("title").value =
    poem.title;

  $("body").value =
    poem.body;

  $("poemError").textContent = "";

  $("poemDialog").showModal();
}

$("poemCancel").onclick = () => {

  $("poemDialog").close();

};

$("poemForm").onsubmit = async event => {

  event.preventDefault();

  $("poemError").textContent = "";

  try {

    const data = {
      title: $("title").value.trim(),
      body: $("body").value
    };

    if (editingId) {

      await api(
        "/api/poems/" + editingId,
        {
          method: "PUT",
          body: JSON.stringify(data)
        }
      );

    } else {

      await api(
        "/api/poems",
        {
          method: "POST",
          body: JSON.stringify(data)
        }
      );

    }

    $("poemDialog").close();

    await loadPoems();

    editingId = null;

  } catch (error) {

    $("poemError").textContent =
      error.message;

  }
};

(async () => {

  try {

    await setup();

  } catch {}

  try {

    await loadUser();
    await loadPoems();

  } catch (error) {

    $("poems").innerHTML =
      '<div class="empty">' +
      escapeText(error.message) +
      "</div>";

  }

})();

</script>

</body>
</html>`;
}

export default {

  async fetch(request, env) {

    try {

      await setup(env);

      const url =
        new URL(request.url);

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {

        return new Response(
          page(),
          {
            headers: {
              "Content-Type":
                "text/html; charset=UTF-8"
            }
          }
        );

      }

      if (
        request.method === "GET" &&
        url.pathname === "/api/me"
      ) {

        return json({
          user: await getUser(
            request,
            env
          )
        });

      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/register"
      ) {

        const data =
          await request.json();

        const username =
          String(
            data.username || ""
          ).trim();

        const password =
          String(
            data.password || ""
          );

        if (
          !/^[A-Za-z0-9_]{3,30}$/.test(
            username
          )
        ) {

          return json(
            {
              error:
                "Username must be 3-30 characters."
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
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
          )
          .bind(username)
          .first();

        if (existing) {

          return json(
            {
              error:
                "That username is already taken."
            },
            400
          );

        }

        const count =
          await env.DB.prepare(
            "SELECT COUNT(*) AS count FROM users"
          ).first();

        const isAdmin =
          Number(count.count) === 0
            ? 1
            : 0;

        const passwordHash =
          await passwordHash(password);

        const result =
          await env.DB.prepare(`
            INSERT INTO users
            (username, password_hash, is_admin)
            VALUES (?, ?, ?)
          `)
          .bind(
            username,
            passwordHash,
            isAdmin
          )
          .run();

        const token =
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
            "Set-Cookie":
              makeCookie(token)
          }
        );
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/login"
      ) {

        const data =
          await request.json();

        const username =
          String(
            data.username || ""
          ).trim();

        const password =
          String(
            data.password || ""
          );

        const user =
          await env.DB.prepare(`
            SELECT *
            FROM users
            WHERE username = ?
            COLLATE NOCASE
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

        const hash =
          await passwordHash(password);

        if (
          hash !== user.password_hash
        ) {

          return json(
            {
              error:
                "Incorrect username or password."
            },
            401
          );

        }

        const token =
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
            "Set-Cookie":
              makeCookie(token)
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
            "Set-Cookie":
              makeCookie("", 0)
          }
        );
      }

      if (
        request.method === "GET" &&
        url.pathname === "/api/poems"
      ) {

        const result =
          await env.DB.prepare(`
            SELECT
              poems.id,
              poems.user_id,
              poems.title,
              poems.body,
              poems.created_at,
              poems.updated_at,
              users.username
            FROM poems
            JOIN users
              ON users.id = poems.user_id
            ORDER BY poems.id DESC
          `)
          .all();

        return json({
          poems:
            result.results || []
        });
      }

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

        const data =
          await request.json();

        const title =
          String(
            data.title || ""
          ).trim();

        const body =
          String(
            data.body || ""
          );

        if (!title || !body.trim()) {

          return json(
            {
              error:
                "Title and poem are required."
            },
            400
          );

        }

        await env.DB.prepare(`
          INSERT INTO poems
          (user_id, title, body)
          VALUES (?, ?, ?)
        `)
        .bind(
          user.id,
          title,
          body
        )
        .run();

        return json({
          ok: true
        });
      }

      const match =
        url.pathname.match(
          /^\/api\/poems\/([0-9]+)$/
        );

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

        const id =
          Number(match[1]);

        const poem =
          await env.DB.prepare(
            "SELECT * FROM poems WHERE id = ?"
          )
          .bind(id)
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
                "You cannot edit this poem."
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

        const data =
          await request.json();

        const title =
          String(
            data.title || ""
          ).trim();

        const body =
          String(
            data.body || ""
          );

        if (!title || !body.trim()) {

          return json(
            {
              error:
                "Title and poem are required."
            },
            400
          );

        }

        await env.DB.prepare(`
          UPDATE poems
          SET
            title = ?,
            body = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          title,
          body,
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

      console.error(error);

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
