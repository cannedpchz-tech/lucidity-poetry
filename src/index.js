const encoder = new TextEncoder();

const COOKIE_NAME = "lucidity_session";
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

function randomHex(bytes) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  let result = "";

  for (const byte of array) {
    result += byte.toString(16).padStart(2, "0");
  }

  return result;
}

async function sha256(value) {
  const data = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  let result = "";

  for (const byte of new Uint8Array(data)) {
    result += byte.toString(16).padStart(2, "0");
  }

  return result;
}

async function hashPassword(password, saltHex) {
  let salt;

  if (saltHex) {
    const parts = saltHex.match(/../g) || [];
    salt = new Uint8Array(
      parts.map(function (x) {
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

  let saltString = "";
  let hashString = "";

  for (const byte of salt) {
    saltString += byte.toString(16).padStart(2, "0");
  }

  for (const byte of new Uint8Array(bits)) {
    hashString += byte.toString(16).padStart(2, "0");
  }

  return saltString + ":" + hashString;
}

async function verifyPassword(password, stored) {
  if (!stored || stored.indexOf(":") === -1) {
    return false;
  }

  const parts = stored.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const calculated = await hashPassword(password, parts[0]);

  return calculated === stored;
}

function getCookie(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = header.split(";");

  for (const cookie of cookies) {
    const trimmed = cookie.trim();

    if (trimmed.indexOf(COOKIE_NAME + "=") === 0) {
      return decodeURIComponent(
        trimmed.substring(COOKIE_NAME.length + 1)
      );
    }
  }

  return null;
}

function makeCookie(token, maxAge) {
  return (
    COOKIE_NAME +
    "=" +
    encodeURIComponent(token) +
    "; Max-Age=" +
    maxAge +
    "; Path=/; HttpOnly; Secure; SameSite=Lax"
  );
}

function escapeHTML(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function getDatabaseInfo(env) {
  const users = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  const poems = await env.DB
    .prepare("PRAGMA table_info(poems)")
    .all();

  const userColumns = new Set();

  for (const column of users.results || []) {
    userColumns.add(column.name);
  }

  const poemColumns = new Set();

  for (const column of poems.results || []) {
    poemColumns.add(column.name);
  }

  return {
    hasAdmin: userColumns.has("is_admin"),
    hasRole: userColumns.has("role"),
    hasSessionToken: userColumns.has("session_token"),
    hasPasswordHash: userColumns.has("password_hash"),
    hasPoemCreated: poemColumns.has("created_at"),
    hasPoemUpdated: poemColumns.has("updated_at")
  };
}

async function ensureSessions(env) {
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

async function createSession(userId, env) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expires =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  const info = await getDatabaseInfo(env);

  if (info.hasSessionToken) {
    await env.DB
      .prepare(
        "UPDATE users SET session_token = ? WHERE id = ?"
      )
      .bind(tokenHash, userId)
      .run();

    return token;
  }

  await ensureSessions(env);

  await env.DB
    .prepare(
      "DELETE FROM sessions WHERE user_id = ?"
    )
    .bind(userId)
    .run();

  await env.DB
    .prepare(
      "INSERT INTO sessions(token_hash,user_id,expires_at) " +
      "VALUES(?,?,?)"
    )
    .bind(tokenHash, userId, expires)
    .run();

  return token;
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);
  const info = await getDatabaseInfo(env);

  if (info.hasSessionToken) {
    let adminSQL = "0";

    if (info.hasAdmin) {
      adminSQL = "is_admin";
    } else if (info.hasRole) {
      adminSQL = "CASE WHEN role = 'admin' THEN 1 ELSE 0 END";
    }

    const user = await env.DB
      .prepare(
        "SELECT id, username, " +
        adminSQL +
        " AS admin_value FROM users " +
        "WHERE session_token = ?"
      )
      .bind(tokenHash)
      .first();

    if (!user) {
      return null;
    }

    return {
      id: user.id,
      username: user.username,
      is_admin: Number(user.admin_value) === 1
    };
  }

  await ensureSessions(env);

  let adminSQL = "0";

  if (info.hasAdmin) {
    adminSQL = "u.is_admin";
  } else if (info.hasRole) {
    adminSQL =
      "CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END";
  }

  const user = await env.DB
    .prepare(
      "SELECT u.id, u.username, " +
      adminSQL +
      " AS admin_value " +
      "FROM sessions s JOIN users u ON u.id = s.user_id " +
      "WHERE s.token_hash = ? AND s.expires_at > ?"
    )
    .bind(
      tokenHash,
      Math.floor(Date.now() / 1000)
    )
    .first();

  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    is_admin: Number(user.admin_value) === 1
  };
}

async function deleteSession(request, env) {
  const token = getCookie(request);

  if (!token) {
    return;
  }

  const tokenHash = await sha256(token);
  const info = await getDatabaseInfo(env);

  if (info.hasSessionToken) {
    await env.DB
      .prepare(
        "UPDATE users SET session_token = NULL " +
        "WHERE session_token = ?"
      )
      .bind(tokenHash)
      .run();

    return;
  }

  await ensureSessions(env);

  await env.DB
    .prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    )
    .bind(tokenHash)
    .run();
}

async function createUser(env, username, password) {
  const info = await getDatabaseInfo(env);

  const existing = await env.DB
    .prepare(
      "SELECT id FROM users " +
      "WHERE username = ? COLLATE NOCASE"
    )
    .bind(username)
    .first();

  if (existing) {
    throw new Error("That username is already taken.");
  }

  const count = await env.DB
    .prepare("SELECT COUNT(*) AS total FROM users")
    .first();

  const firstUser =
    Number(count && count.total ? count.total : 0) === 0;

  const passwordHash =
    await hashPassword(password);

  let result;

  if (info.hasAdmin) {
    result = await env.DB
      .prepare(
        "INSERT INTO users(username,password_hash,is_admin) " +
        "VALUES(?,?,?)"
      )
      .bind(
        username,
        passwordHash,
        firstUser ? 1 : 0
      )
      .run();
  } else if (info.hasRole) {
    result = await env.DB
      .prepare(
        "INSERT INTO users(username,password_hash,role) " +
        "VALUES(?,?,?)"
      )
      .bind(
        username,
        passwordHash,
        firstUser ? "admin" : "user"
      )
      .run();
  } else {
    throw new Error(
      "Your users table needs either an is_admin or role column."
    );
  }

  return {
    id: result.meta.last_row_id,
    is_admin: firstUser
  };
}

function pageHTML() {
  const html = [
    "<!doctype html>",
    "<html lang='en'>",
    "<head>",
    "<meta charset='utf-8'>",
    "<meta name='viewport' content='width=device-width,initial-scale=1'>",
    "<title>Lucidity - Poetry</title>",
    "<style>",
    ":root{--paper:#f4efe6;--ink:#1b1a18;--muted:#746f66;--line:#d8d0c3;--card:#fbf8f1;--accent:#6e4e8f;--danger:#9d3d3d}",
    "*{box-sizing:border-box}",
    "html{scroll-behavior:smooth}",
    "body{margin:0;background:var(--paper);color:var(--ink);font-family:Georgia,'Times New Roman',serif}",
    "button,input,textarea{font:inherit}",
    ".site{max-width:1120px;margin:auto;padding:0 22px}",
    ".top{border-bottom:1px solid var(--line);background:rgba(244,239,230,.94);backdrop-filter:blur(12px);position:sticky;top:0;z-index:10}",
    ".nav{height:72px;display:flex;align-items:center;justify-content:space-between;gap:18px}",
    ".brand{font-size:23px;font-weight:bold}",
    ".brand small{display:block;font-family:system-ui,sans-serif;color:var(--muted);font-size:9px;letter-spacing:3px;text-transform:uppercase}",
    ".navRight{display:flex;align-items:center;gap:10px}",
    ".pill{font:600 12px system-ui,sans-serif;color:var(--muted)}",
    ".hero{padding:78px 0 62px;display:grid;grid-template-columns:1.4fr .8fr;gap:55px;align-items:end}",
    ".eyebrow{font:700 11px system-ui,sans-serif;letter-spacing:3px;text-transform:uppercase;color:var(--accent);margin-bottom:18px}",
    ".hero h1{font-size:clamp(52px,8vw,92px);line-height:.88;margin:0;letter-spacing:-3px;font-weight:500}",
    ".hero p{font-size:20px;line-height:1.55;color:var(--muted);margin:0}",
    ".credit{margin-top:18px;color:var(--muted);font:12px system-ui,sans-serif}",
    ".rule{height:1px;background:var(--line)}",
    ".toolbar{display:flex;justify-content:space-between;align-items:center;padding:24px 0 18px;gap:12px}",
    ".toolbar h2{font-size:20px;font-weight:500;margin:0}",
    "button{cursor:pointer;border:1px solid var(--ink);border-radius:999px;padding:10px 16px;background:var(--ink);color:white;font-family:system-ui,sans-serif;font-size:13px;font-weight:700}",
    "button.secondary{background:transparent;color:var(--ink);border-color:var(--line)}",
    "button.danger{background:transparent;color:var(--danger);border-color:#d7aaa5}",
    ".feed{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;padding-bottom:90px}",
    ".poem{background:var(--card);border:1px solid var(--line);padding:28px;border-radius:3px;min-height:260px;display:flex;flex-direction:column;box-shadow:0 14px 45px rgba(35,28,18,.08)}",
    ".poem.admin{border-top:3px solid var(--accent)}",
    ".poemTitle{font-size:29px;line-height:1.1;margin:0 0 8px;font-weight:500}",
    ".meta{font:12px system-ui,sans-serif;color:var(--muted);margin-bottom:22px}",
    ".poemBody{white-space:pre-wrap;line-height:1.85;font-size:17px;flex:1}",
    ".actions{display:flex;gap:8px;margin-top:24px}",
    ".empty{grid-column:1/-1;padding:65px 20px;text-align:center;border:1px dashed var(--line);color:var(--muted);font-size:17px}",
    "dialog{width:min(580px,calc(100% - 28px));border:1px solid var(--line);background:var(--card);color:var(--ink);padding:0;border-radius:4px;box-shadow:0 30px 100px rgba(0,0,0,.25)}",
    "dialog::backdrop{background:rgba(25,20,15,.5);backdrop-filter:blur(3px)}",
    ".modal{padding:30px}",
    ".modal h2{font-size:34px;font-weight:500;margin:0 0 4px}",
    ".sub{color:var(--muted);font:13px system-ui,sans-serif;margin-bottom:22px}",
    "label{display:block;font:700 12px system-ui,sans-serif;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin:15px 0 7px}",
    "input,textarea{width:100%;border:1px solid var(--line);background:#fffdf8;color:var(--ink);padding:13px;border-radius:2px;outline:none}",
    "textarea{min-height:260px;resize:vertical;line-height:1.7}",
    ".formActions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}",
    ".error{min-height:20px;color:var(--danger);font:13px system-ui,sans-serif;margin-top:10px}",
    ".switch{text-align:center;margin:18px 0 0;font:13px system-ui,sans-serif;color:var(--muted)}",
    ".switch a{color:var(--accent);font-weight:700;cursor:pointer}",
    ".toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:white;padding:12px 17px;border-radius:999px;font:13px system-ui,sans-serif;opacity:0;transition:.2s;z-index:50}",
    ".toast.show{opacity:1}",
    "@media(max-width:760px){.hero{grid-template-columns:1fr;gap:24px;padding:55px 0 45px}.feed{grid-template-columns:1fr}.pill{display:none}.site{padding:0 15px}}",
    "</style>",
    "</head>",
    "<body>",

    "<header class='top'>",
    "<nav class='site nav'>",
    "<div class='brand'>Lucidity<small>Poetry Archive</small></div>",
    "<div class='navRight'><span class='pill' id='who'></span><button class='secondary' id='authButton'>Log in</button></div>",
    "</nav>",
    "</header>",

    "<main class='site'>",

    "<section class='hero'>",
    "<div>",
    "<div class='eyebrow'>A place for words</div>",
    "<h1>Write what<br>you cannot say.</h1>",
    "<div class='credit'>A poetry archive by Juan Pablo F.</div>",
    "</div>",
    "<p>Poems by people who wanted their words to exist somewhere outside their heads.</p>",
    "</section>",

    "<div class='rule'></div>",

    "<section class='toolbar'>",
    "<h2>Recent poems</h2>",
    "<button id='newButton'>Write a poem</button>",
    "</section>",

    "<section id='feed' class='feed'>",
    "<div class='empty'>Loading poems...</div>",
    "</section>",

    "</main>",

    "<div id='toast' class='toast'></div>",

    "<dialog id='authDialog'>",
    "<div class='modal'>",
    "<h2 id='authHeading'>Log in</h2>",
    "<div class='sub' id='authSub'>Return to your writing.</div>",
    "<form id='authForm'>",
    "<label>Username</label>",
    "<input id='username' autocomplete='username' required minlength='3' maxlength='30'>",
    "<label>Password</label>",
    "<input id='password' type='password' autocomplete='current-password' required minlength='8'>",
    "<div id='authError' class='error'></div>",
    "<div class='formActions'>",
    "<button type='button' class='secondary' id='authCancel'>Cancel</button>",
    "<button id='authSubmit'>Log in</button>",
    "</div>",
    "</form>",
    "<div class='switch'><span id='switchLabel'>New here?</span> <a id='switchAuth'>Create an account</a></div>",
    "</div>",
    "</dialog>",

    "<dialog id='poemDialog'>",
    "<div class='modal'>",
    "<h2 id='poemHeading'>Write a poem</h2>",
    "<div class='sub'>Put it here. You can change or remove it later.</div>",
    "<form id='poemForm'>",
    "<label>Title</label>",
    "<input id='poemTitle' maxlength='120' required>",
    "<label>Your poem</label>",
    "<textarea id='poemBody' maxlength='20000' required></textarea>",
    "<div id='poemError' class='error'></div>",
    "<div class='formActions'>",
    "<button type='button' class='secondary' id='poemCancel'>Cancel</button>",
    "<button id='poemSubmit'>Publish poem</button>",
    "</div>",
    "</form>",
    "</div>",
    "</dialog>",

    "<script>",
    "(function(){",

    "var state={user:null,editingId:null,authMode:'login'};",

    "function $(id){return document.getElementById(id)}",

    "function toast(message){",
    "var t=$('toast');",
    "t.textContent=message;",
    "t.classList.add('show');",
    "clearTimeout(toast.timer);",
    "toast.timer=setTimeout(function(){t.classList.remove('show')},2500);",
    "}",

    "async function api(url,options){",
    "options=options||{};",
    "options.headers=Object.assign({'content-type':'application/json'},options.headers||{});",
    "var response=await fetch(url,options);",
    "var data={};",
    "try{data=await response.json()}catch(e){}",
    "if(!response.ok){throw new Error(data.error||('Request failed ('+response.status+')'))}",
    "return data;",
    "}",

    "function openAuth(mode){",
    "state.authMode=mode||'login';",
    "renderAuth();",
    "$('authDialog').showModal();",
    "setTimeout(function(){$('username').focus()},50);",
    "}",

    "function renderAuth(){",
    "var register=state.authMode==='register';",
    "$('authHeading').textContent=register?'Create an account':'Log in';",
    "$('authSub').textContent=register?'Create a place for your words.':'Return to your writing.';",
    "$('authSubmit').textContent=register?'Create account':'Log in';",
    "$('switchLabel').textContent=register?'Already have an account?':'New here?';",
    "$('switchAuth').textContent=register?'Log in':'Create an account';",
    "$('authError').textContent='';",
    "}",

    "async function refreshUser(){",
    "var data=await api('/api/me');",
    "state.user=data.user;",
    "if(state.user){",
    "$('who').textContent='@'+state.user.username+(state.user.is_admin?' - ADMIN':'');",
    "$('authButton').textContent='Log out';",
    "}else{",
    "$('who').textContent='';",
    "$('authButton').textContent='Log in';",
    "}",
    "}",

    "async function loadPoems(){",
    "var data=await api('/api/poems');",
    "var feed=$('feed');",
    "if(!data.poems||data.poems.length===0){",
    "feed.innerHTML='<div class=\"empty\">No poems yet.<br><br>Be the first person to leave a few words here.</div>';",
    "return;",
    "}",

    "feed.innerHTML=data.poems.map(function(poem){",
    "var can=state.user&&(state.user.is_admin||Number(state.user.id)===Number(poem.user_id));",
    "var actions='';",
    "if(can){",
    "actions='<div class=\"actions\">'+",
    "'<button class=\"secondary edit\" data-id=\"'+poem.id+'\">Edit</button>'+",
    "'<button class=\"danger delete\" data-id=\"'+poem.id+'\">Delete</button>'+",
    "'</div>';",
    "}",
    "return '<article class=\"poem\">'+",
    "'<h3 class=\"poemTitle\">'+escapeClient(poem.title)+'</h3>'+",
    "'<div class=\"meta\">by @'+escapeClient(poem.username)+'</div>'+",
    "'<div class=\"poemBody\">'+escapeClient(poem.body)+'</div>'+",
    actions+'</article>';",
    "}).join('');",

    "feed.querySelectorAll('.edit').forEach(function(button){",
    "button.addEventListener('click',async function(){",
    "var id=Number(button.dataset.id);",
    "var poem=data.poems.find(function(x){return Number(x.id)===id});",
    "if(!poem)return;",
    "state.editingId=id;",
    "$('poemHeading').textContent='Edit poem';",
    "$('poemSubmit').textContent='Save changes';",
    "$('poemTitle').value=poem.title;",
    "$('poemBody').value=poem.body;",
    "$('poemError').textContent='';",
    "$('poemDialog').showModal();",
    "});",
    "});",

    "feed.querySelectorAll('.delete').forEach(function(button){",
    "button.addEventListener('click',async function(){",
    "if(!confirm('Delete this poem? This cannot be undone.'))return;",
    "try{",
    "await api('/api/poems/'+button.dataset.id,{method:'DELETE'});",
    "toast('Poem deleted.');",
    "await loadPoems();",
    "}catch(error){toast(error.message)}",
    "});",
    "});",
    "}",

    "function escapeClient(value){",
    "return String(value==null?'':value).replace(/[&<>\"']/g,function(c){",
    "return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c];",
    "});",
    "}",

    "$('authButton').addEventListener('click',async function(){",
    "if(!state.user){openAuth('login');return;}",
    "try{",
    "await api('/api/logout',{method:'POST'});",
    "await refreshUser();",
    "await loadPoems();",
    "toast('Logged out.');",
    "}catch(error){toast(error.message)}",
    "});",

    "$('newButton').addEventListener('click',function(){",
    "if(!state.user){openAuth('login');return;}",
    "state.editingId=null;",
    "$('poemHeading').textContent='Write a poem';",
    "$('poemSubmit').textContent='Publish poem';",
    "$('poemTitle').value='';",
    "$('poemBody').value='';",
    "$('poemError').textContent='';",
    "$('poemDialog').showModal();",
    "});",

    "$('authCancel').addEventListener('click',function(){$('authDialog').close()});",
    "$('poemCancel').addEventListener('click',function(){$('poemDialog').close()});",

    "$('switchAuth').addEventListener('click',function(){",
    "state.authMode=state.authMode==='login'?'register':'login';",
    "renderAuth();",
    "});",

    "$('authForm').addEventListener('submit',async function(event){",
    "event.preventDefault();",
    "$('authError').textContent='';",
    "try{",
    "await api('/api/'+state.authMode,{",
    "method:'POST',",
    "body:JSON.stringify({username:$('username').value.trim(),password:$('password').value})",
    "});",
    "$('authDialog').close();",
    "$('authForm').reset();",
    "await refreshUser();",
    "await loadPoems();",
    "toast(state.authMode==='register'?'Account created.':'Welcome back.');",
    "}catch(error){$('authError').textContent=error.message}",
    "});",

    "$('poemForm').addEventListener('submit',async function(event){",
    "event.preventDefault();",
    "$('poemError').textContent='';",
    "var payload={title:$('poemTitle').value.trim(),body:$('poemBody').value};",
    "try{",
    "if(state.editingId){",
    "await api('/api/poems/'+state.editingId,{method:'PUT',body:JSON.stringify(payload)});",
    "}else{",
    "await api('/api/poems',{method:'POST',body:JSON.stringify(payload)});",
    "}",
    "$('poemDialog').close();",
    "await loadPoems();",
    "toast(state.editingId?'Poem updated.':'Poem published.');",
    "state.editingId=null;",
    "}catch(error){$('poemError').textContent=error.message}",
    "});",

    "refreshUser().then(loadPoems).catch(function(error){",
    "console.error(error);",
    "$('feed').innerHTML='<div class=\"empty\">The site could not load its data.<br><br>'+escapeClient(error.message)+'</div>';",
    "});",

    "})();",
    "</script>",
    "</body>",
    "</html>"
  ];

  return html.join("\n");
}

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/") {
    return new Response(pageHTML(), {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store"
      }
    });
  }

  if (request.method === "GET" && url.pathname === "/api/me") {
    return json({
      user: await getUser(request, env)
    });
  }

  if (request.method === "POST" && url.pathname === "/api/register") {
    let body;

    try {
      body = await request.json();
    } catch (error) {
      return json({ error: "Invalid request." }, 400);
    }

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

    if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
      return json({
        error:
          "Username must be 3-30 characters using letters, numbers, or underscores."
      }, 400);
    }

    if (password.length < 8) {
      return json({
        error: "Password must be at least 8 characters."
      }, 400);
    }

    try {
      const user =
        await createUser(env, username, password);

      const token =
        await createSession(user.id, env);

      return json(
        {
          ok: true,
          user: {
            id: user.id,
            username: username,
            is_admin: user.is_admin
          }
        },
        200,
        {
          "set-cookie":
            makeCookie(token, SESSION_SECONDS)
        }
      );
    } catch (error) {
      console.error(error);

      return json({
        error:
          error.message ||
          "Could not create account."
      }, 500);
    }
  }

  if (request.method === "POST" && url.pathname === "/api/login") {
    let body;

    try {
      body = await request.json();
    } catch (error) {
      return json({ error: "Invalid request." }, 400);
    }

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

    const user =
      await env.DB
        .prepare(
          "SELECT * FROM users " +
          "WHERE username = ? COLLATE NOCASE"
        )
        .bind(username)
        .first();

    if (!user) {
      return json({
        error: "Incorrect username or password."
      }, 401);
    }

    const valid =
      await verifyPassword(
        password,
        user.password_hash
      );

    if (!valid) {
      return json({
        error: "Incorrect username or password."
      }, 401);
    }

    const token =
      await createSession(user.id, env);

    const info =
      await getDatabaseInfo(env);

    let admin = false;

    if (info.hasAdmin) {
      admin = Number(user.is_admin) === 1;
    } else if (info.hasRole) {
      admin = user.role === "admin";
    }

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          is_admin: admin
        }
      },
      200,
      {
        "set-cookie":
          makeCookie(token, SESSION_SECONDS)
      }
    );
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    await deleteSession(request, env);

    return json(
      { ok: true },
      200,
      {
        "set-cookie": makeCookie("", 0)
      }
    );
  }

  if (request.method === "GET" && url.pathname === "/api/poems") {
    const result =
      await env.DB
        .prepare(
          "SELECT p.id,p.user_id,p.title,p.body," +
          "p.created_at,p.updated_at,u.username " +
          "FROM poems p JOIN users u ON u.id=p.user_id " +
          "ORDER BY p.id DESC"
        )
        .all();

    return json({
      poems: result.results || []
    });
  }

  if (request.method === "POST" && url.pathname === "/api/poems") {
    const user =
      await getUser(request, env);

    if (!user) {
      return json({
        error: "You must be logged in."
      }, 401);
    }

    let body;

    try {
      body = await request.json();
    } catch (error) {
      return json({
        error: "Invalid request."
      }, 400);
    }

    const title =
      String(body.title || "").trim();

    const poem =
      String(body.body || "");

    if (!title || !poem.trim()) {
      return json({
        error: "Title and poem text are required."
      }, 400);
    }

    if (title.length > 120 || poem.length > 20000) {
      return json({
        error: "Poem is too long."
      }, 400);
    }

    await env.DB
      .prepare(
        "INSERT INTO poems(user_id,title,body) VALUES(?,?,?)"
      )
      .bind(user.id, title, poem)
      .run();

    return json({ ok: true });
  }

  if (
    url.pathname.indexOf("/api/poems/") === 0
  ) {
    const idText =
      url.pathname.substring("/api/poems/".length);

    const id =
      Number(idText);

    if (!Number.isInteger(id) || id <= 0) {
      return json({
        error: "Invalid poem ID."
      }, 400);
    }

    const user =
      await getUser(request, env);

    if (!user) {
      return json({
        error: "You must be logged in."
      }, 401);
    }

    const poem =
      await env.DB
        .prepare(
          "SELECT * FROM poems WHERE id = ?"
        )
        .bind(id)
        .first();

    if (!poem) {
      return json({
        error: "Poem not found."
      }, 404);
    }

    if (
      !user.is_admin &&
      Number(poem.user_id) !== Number(user.id)
    ) {
      return json({
        error:
          "You can only modify your own poems."
      }, 403);
    }

    if (request.method === "DELETE") {
      await env.DB
        .prepare(
          "DELETE FROM poems WHERE id = ?"
        )
        .bind(id)
        .run();

      return json({ ok: true });
    }

    if (request.method === "PUT") {
      let body;

      try {
        body = await request.json();
      } catch (error) {
        return json({
          error: "Invalid request."
        }, 400);
      }

      const title =
        String(body.title || "").trim();

      const poemBody =
        String(body.body || "");

      if (!title || !poemBody.trim()) {
        return json({
          error:
            "Title and poem text are required."
        }, 400);
      }

      if (
        title.length > 120 ||
        poemBody.length > 20000
      ) {
        return json({
          error: "Poem is too long."
        }, 400);
      }

      await env.DB
        .prepare(
          "UPDATE poems SET title=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?"
        )
        .bind(title, poemBody, id)
        .run();

      return json({ ok: true });
    }

    return json({
      error: "Method not allowed."
    }, 405);
  }

  return new Response("Not found", {
    status: 404
  });
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error("WORKER ERROR:", error);

      return json({
        error:
          error.message ||
          "Server error."
      }, 500);
    }
  }
};
