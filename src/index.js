const encoder = new TextEncoder();
const COOKIE = "lucidity_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", ...headers }
});

function htmlEscape(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function randomHex(bytes = 32) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return [...a].map(x => x.toString(16).padStart(2,"0")).join(""); }
async function sha256(value) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)))].map(x=>x.toString(16).padStart(2,"0")).join(""); }
async function hashPassword(password, saltHex = null) {
  const salt = saltHex ? Uint8Array.from((saltHex.match(/../g)||[]).map(x=>parseInt(x,16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt, iterations:150000, hash:"SHA-256"}, key, 256);
  return [...salt].map(x=>x.toString(16).padStart(2,"0")).join("")+":"+[...new Uint8Array(bits)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function verifyPassword(password, stored) { const [salt, hash] = stored.split(":"); return (await hashPassword(password, salt)) === `${salt}:${hash}`; }
function getCookie(request) { const cookies = request.headers.get("Cookie") || ""; const item = cookies.split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"=")); return item ? decodeURIComponent(item.slice(COOKIE.length+1)) : null; }
function cookie(token, maxAge = SESSION_SECONDS) { return `${COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`; }
async function getUser(request, env) {
  const token = getCookie(request); if (!token) return null;
  return await env.DB.prepare(`SELECT u.id,u.username,u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).bind(await sha256(token), Math.floor(Date.now()/1000)).first();
}
async function requireUser(request, env) { const u=await getUser(request,env); if(!u) return null; return {...u,is_admin:!!u.is_admin}; }
async function createSession(userId, env) { const token=randomHex(32); await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await sha256(token),userId,Math.floor(Date.now()/1000)+SESSION_SECONDS).run(); return token; }

function appHTML() { return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#f4efe6"><title>Lucidity — Poetry</title>
<style>
:root{--paper:#f4efe6;--ink:#1b1a18;--muted:#746f66;--line:#d8d0c3;--card:#fbf8f1;--accent:#6e4e8f;--accent2:#8b6ca8;--danger:#9d3d3d;--shadow:0 14px 45px rgba(35,28,18,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font-family:Georgia,"Times New Roman",serif}button,input,textarea{font:inherit}.site{max-width:1120px;margin:auto;padding:0 22px}.top{border-bottom:1px solid var(--line);background:rgba(244,239,230,.9);backdrop-filter:blur(12px);position:sticky;top:0;z-index:10}.nav{height:72px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-size:23px;font-weight:bold;letter-spacing:.3px}.brand small{display:block;font-family:system-ui,sans-serif;color:var(--muted);font-size:9px;letter-spacing:3px;text-transform:uppercase;margin-top:1px}.navRight{display:flex;align-items:center;gap:10px}.pill{font:600 12px system-ui,sans-serif;color:var(--muted)}
.hero{padding:78px 0 62px;display:grid;grid-template-columns:1.4fr .8fr;gap:55px;align-items:end}.eyebrow{font:700 11px system-ui,sans-serif;letter-spacing:3px;text-transform:uppercase;color:var(--accent);margin-bottom:18px}.hero h1{font-size:clamp(52px,8vw,92px);line-height:.88;margin:0;letter-spacing:-3px;font-weight:500}.hero p{font-size:20px;line-height:1.55;color:var(--muted);margin:0 0 4px}.rule{height:1px;background:var(--line)}
.toolbar{display:flex;justify-content:space-between;align-items:center;padding:24px 0 18px;gap:12px}.toolbar h2{font-size:20px;font-weight:500;margin:0}.buttons{display:flex;gap:9px;flex-wrap:wrap}button{cursor:pointer;border:1px solid var(--ink);border-radius:999px;padding:10px 16px;background:var(--ink);color:#fff;font-family:system-ui,sans-serif;font-size:13px;font-weight:700}button.secondary{background:transparent;color:var(--ink);border-color:var(--line)}button.danger{background:transparent;color:var(--danger);border-color:#d7aaa5}
.feed{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;padding-bottom:90px}.poem{background:var(--card);border:1px solid var(--line);padding:28px;border-radius:3px;box-shadow:var(--shadow);min-height:260px;display:flex;flex-direction:column}.poem.admin{border-top:3px solid var(--accent)}.poemTitle{font-size:29px;line-height:1.1;margin:0 0 8px;font-weight:500}.meta{font:12px system-ui,sans-serif;color:var(--muted);margin-bottom:22px}.poemBody{white-space:pre-wrap;line-height:1.85;font-size:17px;flex:1}.actions{display:flex;gap:8px;margin-top:24px}.empty{grid-column:1/-1;padding:65px 20px;text-align:center;border:1px dashed var(--line);color:var(--muted);font-size:17px}
dialog{width:min(580px,calc(100% - 28px));border:1px solid var(--line);background:var(--card);color:var(--ink);padding:0;border-radius:4px;box-shadow:0 30px 100px rgba(0,0,0,.25)}dialog::backdrop{background:rgba(25,20,15,.5);backdrop-filter:blur(3px)}.modal{padding:30px}.modal h2{font-size:34px;font-weight:500;margin:0 0 4px}.sub{color:var(--muted);font:13px system-ui,sans-serif;margin-bottom:22px}label{display:block;font:700 12px system-ui,sans-serif;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin:15px 0 7px}input,textarea{width:100%;border:1px solid var(--line);background:#fffdf8;color:var(--ink);padding:13px;border-radius:2px;outline:none}input:focus,textarea:focus{border-color:var(--accent)}textarea{min-height:260px;resize:vertical;line-height:1.7}.formActions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}.error{min-height:20px;color:var(--danger);font:13px system-ui,sans-serif;margin-top:10px}.switch{font:13px system-ui,sans-serif;color:var(--muted);text-align:center;margin:18px 0 0}.switch a{color:var(--accent);font-weight:700;cursor:pointer}.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:#fff;padding:12px 17px;border-radius:999px;font:13px system-ui,sans-serif;opacity:0;pointer-events:none;transition:.2s;z-index:50}.toast.show{opacity:1}.loading{color:var(--muted);font:13px system-ui,sans-serif;padding:20px 0}
@media(max-width:760px){.hero{grid-template-columns:1fr;gap:24px;padding:55px 0 45px}.hero h1{letter-spacing:-2px}.feed{grid-template-columns:1fr}.nav{height:64px}.pill{display:none}.site{padding:0 15px}.poem{padding:23px}}
</style></head>
<body><header class="top"><nav class="site nav"><div class="brand">Lucidity<small>Poetry Archive</small></div><div class="navRight"><span class="pill" id="who"></span><button class="secondary" id="authButton">Log in</button></div></nav></header>
<main class="site"><section class="hero"><div><div class="eyebrow">A place for words</div><h1>Write what<br>you cannot say.</h1></div><p>Poems by people who wanted their words to exist somewhere outside their heads.</p></section><div class="rule"></div><section class="toolbar"><h2>Recent poems</h2><div class="buttons"><button id="newButton">Write a poem</button></div></section><section id="feed" class="feed"><div class="loading">Loading poems…</div></section></main>
<div id="toast" class="toast"></div>
<dialog id="authDialog"><div class="modal"><h2 id="authHeading">Log in</h2><div class="sub" id="authSub">Return to your writing.</div><form id="authForm"><label>Username</label><input id="username" autocomplete="username" required minlength="3" maxlength="30"><label>Password</label><input id="password" type="password" autocomplete="current-password" required minlength="8"><div id="authError" class="error"></div><div class="formActions"><button type="button" class="secondary" id="authCancel">Cancel</button><button id="authSubmit">Log in</button></div></form><div class="switch"><span id="switchLabel">New here?</span> <a id="switchAuth">Create an account</a></div></div></dialog>
<dialog id="poemDialog"><div class="modal"><h2 id="poemHeading">Write a poem</h2><div class="sub">Put it here. You can change or remove it later.</div><form id="poemForm"><label>Title</label><input id="poemTitle" maxlength="120" required><label>Your poem</label><textarea id="poemBody" maxlength="20000" required></textarea><div id="poemError" class="error"></div><div class="formActions"><button type="button" class="secondary" id="poemCancel">Cancel</button><button id="poemSubmit">Publish poem</button></div></form></div></dialog>
<script>
(function(){
  const state={user:null,editingId:null,authMode:'login'};
  const $=id=>document.getElementById(id);
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const api=async(url,options={})=>{const r=await fetch(url,{...options,headers:{'content-type':'application/json',...(options.headers||{})}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Something went wrong.');return d};
  function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>t.classList.remove('show'),2500)}
  function openAuth(mode='login'){state.authMode=mode;renderAuth();$('authDialog').showModal();setTimeout(()=>$('username').focus(),50)}
  function renderAuth(){const register=state.authMode==='register';$('authHeading').textContent=register?'Create an account':'Log in';$('authSub').textContent=register?'Your first account becomes the administrator.':'Return to your writing.';$('authSubmit').textContent=register?'Create account':'Log in';$('switchLabel').textContent=register?'Already have an account?':'New here?';$('switchAuth').textContent=register?'Log in':'Create an account';$('authError').textContent=''}
  function openNew(){if(!state.user){openAuth();return}state.editingId=null;$('poemHeading').textContent='Write a poem';$('poemSubmit').textContent='Publish poem';$('poemTitle').value='';$('poemBody').value='';$('poemError').textContent='';$('poemDialog').showModal()}
  function openEdit(id,title,body){state.editingId=id;$('poemHeading').textContent='Edit poem';$('poemSubmit').textContent='Save changes';$('poemTitle').value=title;$('poemBody').value=body;$('poemError').textContent='';$('poemDialog').showModal()}
  async function refreshUser(){const d=await api('/api/me');state.user=d.user;$('who').textContent=state.user?('@'+state.user.username+(state.user.is_admin?' · ADMIN':'')):'';$('authButton').textContent=state.user?'Log out':'Log in'}
  async function loadPoems(){const d=await api('/api/poems');const feed=$('feed');if(!d.poems.length){feed.innerHTML='<div class="empty">No poems yet.<br><br>Be the first person to leave a few words here.</div>';return}feed.innerHTML=d.poems.map(p=>{const can=state.user&&(state.user.is_admin||state.user.id===p.user_id);const admin=state.user&&state.user.is_admin;return '<article class="poem '+(admin?'admin':'')+'"><h3 class="poemTitle">'+esc(p.title)+'</h3><div class="meta">by @'+esc(p.username)+' · '+esc(p.updated_at)+'</div><div class="poemBody">'+esc(p.body)+'</div>'+(can?'<div class="actions"><button class="secondary edit" data-id="'+p.id+'" data-title="'+encodeURIComponent(p.title)+'" data-body="'+encodeURIComponent(p.body)+'">Edit</button><button class="danger delete" data-id="'+p.id+'">Delete</button></div>':'')+'</article>'}).join('');
    feed.querySelectorAll('.edit').forEach(b=>b.addEventListener('click',()=>openEdit(Number(b.dataset.id),decodeURIComponent(b.dataset.title),decodeURIComponent(b.dataset.body))));
    feed.querySelectorAll('.delete').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('Delete this poem? This cannot be undone.'))return;try{await api('/api/poems/'+b.dataset.id,{method:'DELETE'});toast('Poem deleted.');await loadPoems()}catch(e){toast(e.message)}}));
  }
  $('authButton').addEventListener('click',async()=>{if(state.user){await api('/api/logout',{method:'POST'});state.user=null;await refreshUser();await loadPoems();toast('Logged out.')}else openAuth()});
  $('newButton').addEventListener('click',openNew);$('authCancel').addEventListener('click',()=>$('authDialog').close());$('poemCancel').addEventListener('click',()=>$('poemDialog').close());$('switchAuth').addEventListener('click',()=>{state.authMode=state.authMode==='login'?'register':'login';renderAuth()});
  $('authForm').addEventListener('submit',async e=>{e.preventDefault();$('authError').textContent='';try{await api('/api/'+state.authMode,{method:'POST',body:JSON.stringify({username:$('username').value.trim(),password:$('password').value})});$('authDialog').close();$('authForm').reset();await refreshUser();await loadPoems();toast(state.authMode==='register'?'Account created.':'Welcome back.')}catch(err){$('authError').textContent=err.message}});
  $('poemForm').addEventListener('submit',async e=>{e.preventDefault();$('poemError').textContent='';const payload={title:$('poemTitle').value.trim(),body:$('poemBody').value};try{if(state.editingId)await api('/api/poems/'+state.editingId,{method:'PUT',body:JSON.stringify(payload)});else await api('/api/poems',{method:'POST',body:JSON.stringify(payload)});$('poemDialog').close();await loadPoems();toast(state.editingId?'Poem updated.':'Poem published.')}catch(err){$('poemError').textContent=err.message}});
  (async()=>{try{await refreshUser();await loadPoems()}catch(e){$('feed').innerHTML='<div class="empty">The site could not load its data. Please refresh and try again.</div>'}})();
})();
</script></body></html>`; }

export default { async fetch(request, env) {
  const url=new URL(request.url);
  try {
    if(request.method==='GET'&&url.pathname==='/') return new Response(appHTML(),{headers:{'content-type':'text/html;charset=UTF-8','cache-control':'no-store'}});
    if(request.method==='GET'&&url.pathname==='/api/me') return json({user:await getUser(request,env)});
    if(request.method==='POST'&&url.pathname==='/api/register'){
      const {username,password}=await request.json();
      if(!/^[A-Za-z0-9_]{3,30}$/.test(username||''))return json({error:'Username must be 3–30 characters using letters, numbers, or underscores.'},400);
      if(!password||password.length<8)return json({error:'Password must be at least 8 characters.'},400);
      if(await env.DB.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').bind(username).first())return json({error:'That username is already taken.'},409);
      const count=await env.DB.prepare('SELECT COUNT(*) AS count FROM users').first();const admin=Number(count.count)===0;
      const r=await env.DB.prepare('INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,?)').bind(username,await hashPassword(password),admin?1:0).run();
      return json({ok:true},{headers:{'set-cookie':cookie(await createSession(r.meta.last_row_id,env))}});
    }
    if(request.method==='POST'&&url.pathname==='/api/login'){
      const {username,password}=await request.json();const u=await env.DB.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').bind(username||'').first();
      if(!u||!(await verifyPassword(password||'',u.password_hash)))return json({error:'Incorrect username or password.'},401);
      return json({ok:true},{headers:{'set-cookie':cookie(await createSession(u.id,env))}});
    }
    if(request.method==='POST'&&url.pathname==='/api/logout'){
      const token=getCookie(request);if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
      return json({ok:true},{headers:{'set-cookie':cookie('',0)}});
    }
    if(request.method==='GET'&&url.pathname==='/api/poems'){
      const r=await env.DB.prepare('SELECT p.id,p.user_id,p.title,p.body,p.created_at,p.updated_at,u.username FROM poems p JOIN users u ON u.id=p.user_id ORDER BY p.updated_at DESC,p.id DESC').all();return json({poems:r.results});
    }
    if(request.method==='POST'&&url.pathname==='/api/poems'){
      const u=await requireUser(request,env);if(!u)return json({error:'You must be logged in.'},401);const {title,body}=await request.json();
      if(!title?.trim()||!body?.trim())return json({error:'Title and poem text are required.'},400);if(title.length>120||body.length>20000)return json({error:'Poem is too long.'},400);
      await env.DB.prepare('INSERT INTO poems(user_id,title,body) VALUES(?,?,?)').bind(u.id,title.trim(),body).run();return json({ok:true});
    }
    const match=url.pathname.match(/^\/api\/poems\/(\d+)$/);
    if(match&&(request.method==='PUT'||request.method==='DELETE')){
      const u=await requireUser(request,env);if(!u)return json({error:'You must be logged in.'},401);const id=Number(match[1]);const p=await env.DB.prepare('SELECT * FROM poems WHERE id=?').bind(id).first();
      if(!p)return json({error:'Poem not found.'},404);if(!u.is_admin&&p.user_id!==u.id)return json({error:'You can only modify your own poems.'},403);
      if(request.method==='DELETE'){await env.DB.prepare('DELETE FROM poems WHERE id=?').bind(id).run();return json({ok:true});}
      const {title,body}=await request.json();if(!title?.trim()||!body?.trim())return json({error:'Title and poem text are required.'},400);if(title.length>120||body.length>20000)return json({error:'Poem is too long.'},400);
      await env.DB.prepare('UPDATE poems SET title=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(title.trim(),body,id).run();return json({ok:true});
    }
    return new Response('Not found',{status:404});
  } catch(error) { console.error(error); return json({error:'Server error.'},500); }
} };

