'use strict';
/*
 * BLIND HANDOFF — Threat Model Lab, Exercise 2
 * ------------------------------------------------------------
 * A deliberately-hackable classroom web app for teaching identity,
 * authorization, and audit-log forensics.
 *
 * READ THIS FIRST. The whole point of the exercise is that this code is
 * public and imperfect. Several weaknesses below are INTENTIONAL — they are
 * the attack surface students are meant to discover, exploit, and patch.
 * They are all marked with a  >>> WEAKNESS  comment. See README.md.
 *
 * No dependencies. Node 16+.  Run:  node server.js   (or npm start)
 * ------------------------------------------------------------
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const TRUTH_LOG = path.join(__dirname, 'groundtruth.log'); // append-only, instructor-only

// ---------------------------------------------------------------------------
// Data store  (a plain JSON file — easy to read, easy to reset)
// ---------------------------------------------------------------------------
function seed() {
  // >>> WEAKNESS: every player ships with the SAME weak default password.
  // Reused / guessable passwords are part of the attack surface.
  const pw = 'changeme';
  const mk = (team, names) =>
    Object.fromEntries(names.map(n => [n, { password: pw, team, display: n.split('_')[0] }]));
  return {
    config: {
      adminPassword: 'instructor', // used only to create the instructor account below
      defendingTeam: 'blue',
      day: 1,
      sourceUsername: null,
    },
    users: Object.assign(
      { instructor: { password: 'instructor', team: 'admin', display: 'Instructor' } },
      mk('blue', ['maya_b', 'leo_b', 'ava_b', 'sam_b']),
      mk('red', ['dev_r', 'nia_r', 'kai_r', 'zoe_r']),
    ),
    custody: [],          // usernames that currently hold today's secret
    inAppLog: [],         // the log players can see (and the Source can edit)
    messages: [],         // in-app inbox — a phishing vector
    sessions: {},         // token -> username   (persisted, so logins survive restarts)
    scores: { red: 0, blue: 0 },
    scoreLog: [],         // [{time, team, points, reason}]
    nextId: 1,
  };
}

let db;
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
} catch (e) {
  db = seed();
  save();
}
function save() { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function newId() { return db.nextId++; }

// ---------------------------------------------------------------------------
// Logging.  Every event goes to BOTH logs.
//   - inAppLog : what players see; the Source is allowed to delete entries.
//   - TRUTH_LOG: append-only file only the instructor can read. It is never
//                rewritten, so it also records log tampering.
// ---------------------------------------------------------------------------
function logEvent(account, event, device) {
  const entry = { id: newId(), time: now(), account, event, device: device || '—' };
  db.inAppLog.push(entry);
  fs.appendFileSync(TRUTH_LOG, JSON.stringify(entry) + '\n');
  save();
  return entry;
}
function truthOnly(account, event) {
  // Recorded in the ground-truth log only (e.g. tampering the players shouldn't see).
  fs.appendFileSync(TRUTH_LOG, JSON.stringify({ id: newId(), time: now(), account, event, device: 'system' }) + '\n');
}
function now() {
  return new Date().toTimeString().slice(0, 8); // HH:MM:SS
}

// ---------------------------------------------------------------------------
// Tiny HTTP helpers
// ---------------------------------------------------------------------------
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function readBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => (b += c));
    req.on('end', () => {
      const out = {};
      new URLSearchParams(b).forEach((v, k) => (out[k] = v));
      resolve(out);
    });
  });
}
function send(res, status, html, extraHeaders) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, extraHeaders || {}));
  res.end(html);
}
function redirect(res, location, setCookie) {
  const h = { Location: location };
  if (setCookie) h['Set-Cookie'] = setCookie;
  res.writeHead(302, h);
  res.end();
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
function isMobile(ua) {
  // >>> WEAKNESS (intentional design): logins are laptop-only, enforced with a
  // crude, spoofable User-Agent check. Laptops are the devices left unlocked.
  return /Mobi|Android|iPhone|iPad|iPod|Windows Phone|BlackBerry/i.test(ua || '');
}
function deviceLabel(req, token) {
  const ua = req.headers['user-agent'] || '';
  const os = /Mac/i.test(ua) ? 'mac' : /Windows/i.test(ua) ? 'win' : /Linux/i.test(ua) ? 'linux' : 'device';
  return os + '·' + (token || '????').slice(0, 4); // e.g. mac·a1b2
}
function currentUser(req) {
  // >>> WEAKNESS: the session cookie has no HttpOnly / Secure / SameSite flags
  // and never expires — so it is easy to steal, share, and reuse.
  const token = parseCookies(req).sid;
  const uname = token && db.sessions[token];
  if (uname && db.users[uname]) return { name: uname, token, ...db.users[uname] };
  return null;
}

// ---------------------------------------------------------------------------
// Shared page layout (nice-ish; internal pages)
// ---------------------------------------------------------------------------
const CSS = `
  :root{--bg:#0f1220;--panel:#191d31;--ink:#e9ebf5;--muted:#9aa0bd;--line:#2a2f4a;
        --accent:#6366f1;--blue:#3b82f6;--red:#ef4444;--good:#22c55e;--warn:#f59e0b}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
  a{color:#a5b4fc;text-decoration:none} a:hover{text-decoration:underline}
  .top{display:flex;align-items:center;gap:14px;padding:13px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
  .top .brand{font-weight:800;letter-spacing:.3px} .top .brand span{color:var(--accent)}
  .top .who{margin-left:auto;color:var(--muted);font-size:14px}
  .badge{display:inline-block;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;padding:2px 8px;border-radius:999px}
  .badge.blue{background:rgba(59,130,246,.18);color:#93c5fd}
  .badge.red{background:rgba(239,68,68,.18);color:#fca5a5}
  .badge.admin{background:rgba(99,102,241,.18);color:#c7d2fe}
  .wrap{max-width:860px;margin:0 auto;padding:24px 20px 80px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:0 0 16px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
  .status{font-size:20px;font-weight:700;margin:6px 0}
  .status.have{color:var(--good)} .status.nothave{color:var(--muted)}
  .pill{display:inline-block;background:rgba(245,158,11,.16);color:#fcd34d;border-radius:999px;padding:3px 11px;font-size:12.5px;font-weight:700;margin-left:6px}
  label{display:block;font-size:13px;color:var(--muted);margin:10px 0 4px}
  input,select{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:#0d1020;color:var(--ink);font-size:15px}
  button,.btn{cursor:pointer;border:none;border-radius:9px;padding:10px 16px;font-size:14px;font-weight:700;background:var(--accent);color:#fff;margin-top:12px}
  button.ghost,.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
  button.danger{background:var(--red)}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
  td.mono,.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  .row{display:flex;gap:10px;flex-wrap:wrap} .row>*{flex:1}
  .msg{border:1px solid var(--line);border-radius:10px;padding:11px 13px;margin-bottom:9px}
  .msg .meta{font-size:12px;color:var(--muted)} .msg .subj{font-weight:700;margin:2px 0}
  .note{color:var(--muted);font-size:13px} .warnbox{border-left:3px solid var(--warn);padding:8px 12px;background:rgba(245,158,11,.08);border-radius:0 8px 8px 0;font-size:13px;margin:10px 0}
  .nav{display:flex;gap:16px;font-size:14px;margin-top:2px}
`;
function layout(title, user, body) {
  const team = user ? user.team : '';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${esc(title)} · Blind Handoff</title><style>${CSS}</style></head><body>
    <div class="top">
      <div class="brand">Blind<span>Handoff</span></div>
      <div class="nav">
        <a href="/">Home</a><a href="/log">Log</a><a href="/inbox">Inbox</a><a href="/account">Account</a>
        ${user ? '<a href="/logout">Log out</a>' : ''}
      </div>
      <div class="who">${user ? esc(user.display) + ' <span class="badge ' + team + '">' + team + '</span>' : ''}</div>
    </div><div class="wrap">${body}</div></body></html>`;
}

// ---------------------------------------------------------------------------
// The cloneable login page.  Deliberately simple and self-contained so that a
// student can View Source and rebuild it as a phishing page in minutes.
// ---------------------------------------------------------------------------
function loginPage(msg) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Blind Handoff</title>
  <style>
    body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
      background:#0f1220;color:#e9ebf5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
    .box{width:340px;background:#191d31;border:1px solid #2a2f4a;border-radius:16px;padding:28px}
    .logo{font-weight:800;font-size:20px;margin-bottom:2px}.logo span{color:#6366f1}
    p.sub{color:#9aa0bd;font-size:13px;margin:0 0 18px}
    label{display:block;font-size:13px;color:#9aa0bd;margin:12px 0 4px}
    input{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #2a2f4a;background:#0d1020;color:#e9ebf5;font-size:15px}
    button{width:100%;margin-top:18px;padding:12px;border:none;border-radius:9px;background:#6366f1;color:#fff;font-weight:700;font-size:15px;cursor:pointer}
    .err{background:rgba(239,68,68,.15);color:#fca5a5;border-radius:8px;padding:9px 11px;font-size:13px;margin-bottom:6px}
  </style></head><body>
  <!-- This sign-in page is intentionally plain so it is easy to clone. That is the phishing lesson. -->
  <div class="box">
    <div class="logo">Blind<span>Handoff</span></div>
    <p class="sub">Sign in with your game account.</p>
    ${msg ? '<div class="err">' + esc(msg) + '</div>' : ''}
    <form method="POST" action="/login">
      <label>Username</label><input name="username" autocomplete="username" autofocus>
      <label>Password</label><input name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div></body></html>`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;
  const method = req.method;
  const user = currentUser(req);

  try {
    // ---- Auth-free routes ----
    if (p === '/login' && method === 'GET') return send(res, 200, loginPage(u.searchParams.get('e')));
    if (p === '/login' && method === 'POST') {
      const b = await readBody(req);
      if (isMobile(req.headers['user-agent']))
        return send(res, 200, loginPage('Logins are allowed from laptops only.'));
      const acct = db.users[b.username];
      if (!acct || acct.password !== b.password)
        return send(res, 200, loginPage('Wrong username or password.'));
      const token = crypto.randomBytes(16).toString('hex');
      db.sessions[token] = b.username;
      save();
      logEvent(b.username, 'login', deviceLabel(req, token));
      // >>> WEAKNESS: cookie is not HttpOnly/Secure/SameSite and sets no expiry.
      return redirect(res, '/', `sid=${token}; Path=/`);
    }
    if (p === '/logout') {
      if (user) { delete db.sessions[user.token]; save(); logEvent(user.name, 'logout', deviceLabel(req, user.token)); }
      return redirect(res, '/login', 'sid=; Path=/; Max-Age=0');
    }

    // ---- Everything below requires a session ----
    if (!user) return redirect(res, '/login');
    if (user.team === 'admin') return adminRoutes(req, res, user, p, method);

    const device = deviceLabel(req, user.token);

    // ---- Player: home / dashboard ----
    if (p === '/' && method === 'GET') return send(res, 200, dashboard(user));

    // ---- Player: pass the secret ----
    if (p === '/pass' && method === 'POST') {
      const b = await readBody(req);
      if (!db.custody.includes(user.name))
        return send(res, 200, dashboard(user, 'You do not hold the secret, so you cannot pass it.'));
      const to = (b.to || '').trim();
      if (!db.users[to])
        return send(res, 200, dashboard(user, 'No such account: ' + to));
      // >>> WEAKNESS: no roster check. A holder may pass custody to ANY account,
      // including an attacker's. Verifying the recipient is Blue's job, not the server's.
      if (!db.custody.includes(to)) db.custody.push(to);
      save();
      logEvent(user.name, 'passed secret to ' + to, device);
      return send(res, 200, dashboard(user, 'Secret passed to ' + esc(to) + '.'));
    }

    // ---- Player: account / change password (no reauth) ----
    if (p === '/account' && method === 'GET') return send(res, 200, accountPage(user));
    if (p === '/account/password' && method === 'POST') {
      const b = await readBody(req);
      // >>> WEAKNESS: changing the password requires NO current-password / reauth.
      // Anyone at an unlocked, logged-in device can silently take over the account.
      db.users[user.name].password = b.password || '';
      save();
      logEvent(user.name, 'changed password', device);
      return send(res, 200, accountPage(user, 'Password changed.'));
    }

    // ---- Player: audit log (view; Source may delete) ----
    if (p === '/log' && method === 'GET') return send(res, 200, logPage(user));
    if (p === '/log/delete' && method === 'POST') {
      const b = await readBody(req);
      // Only the Source may edit the log.
      if (user.name !== db.config.sourceUsername)
        return send(res, 200, logPage(user, 'Only today’s Source can edit the log.'));
      const id = parseInt(b.id, 10);
      const before = db.inAppLog.length;
      db.inAppLog = db.inAppLog.filter(e => e.id !== id);
      save();
      // >>> WEAKNESS: the deletion leaves NO trace in the in-app log. It is
      // recorded ONLY in the instructor's ground-truth log.
      if (db.inAppLog.length < before) truthOnly(user.name, 'LOG TAMPER: deleted in-app entry #' + id);
      return redirect(res, '/log');
    }

    // ---- Player: inbox / messaging (a phishing vector) ----
    if (p === '/inbox' && method === 'GET') return send(res, 200, inboxPage(user));
    if (p === '/compose' && method === 'GET') return send(res, 200, composePage(user, u.searchParams.get('to')));
    if (p === '/compose' && method === 'POST') {
      const b = await readBody(req);
      db.messages.push({ id: newId(), time: now(), from: user.name, to: (b.to || '').trim(), subject: b.subject || '', body: b.body || '' });
      save();
      return send(res, 200, inboxPage(user, 'Message sent to ' + esc(b.to) + '.'));
    }

    return send(res, 404, layout('Not found', user, '<div class="card"><h1>404</h1><p class="note">No such page.</p></div>'));
  } catch (err) {
    console.error(err);
    return send(res, 500, 'Server error');
  }
});

// ---------------------------------------------------------------------------
// Player pages
// ---------------------------------------------------------------------------
function dashboard(user, flash) {
  const hasSecret = db.custody.includes(user.name);
  const isSource = user.name === db.config.sourceUsername;
  const options = Object.keys(db.users)
    .filter(n => db.users[n].team !== 'admin')
    .map(n => `<option value="${esc(n)}">${esc(n)} (${db.users[n].team})</option>`).join('');
  return layout('Home', user, `
    ${flash ? '<div class="card"><b>' + esc(flash) + '</b></div>' : ''}
    <div class="card">
      <h1>Today’s status <span class="note" style="font-size:14px">· day ${db.config.day}</span></h1>
      <div class="status ${hasSecret ? 'have' : 'nothave'}">
        ${hasSecret ? '✓ You hold today’s secret' : 'You do not hold today’s secret'}
        ${isSource ? '<span class="pill">You are the Source</span>' : ''}
      </div>
      <p class="note">The secret is never shown to you — it lives on the server. You either hold custody or you don’t.</p>
    </div>
    <div class="card">
      <h2>Pass the secret</h2>
      ${hasSecret
        ? `<form method="POST" action="/pass">
             <label>Pass custody to</label>
             <select name="to">${options}</select>
             <button type="submit">Pass secret</button>
           </form>
           <div class="warnbox">Anyone you name receives it — the server does not check whether they are really your teammate.</div>`
        : '<p class="note">You can only pass the secret on a day you hold it.</p>'}
    </div>
    ${isSource ? '<div class="card"><h2>Source privilege</h2><p class="note">As today’s Source you may delete entries from the <a href="/log">audit log</a>.</p></div>' : ''}
  `);
}

function accountPage(user, flash) {
  return layout('Account', user, `
    ${flash ? '<div class="card"><b>' + esc(flash) + '</b></div>' : ''}
    <div class="card">
      <h1>Account</h1>
      <p class="note">Signed in as <b>${esc(user.name)}</b> (${user.team}).</p>
      <h2 style="margin-top:18px">Change password</h2>
      <form method="POST" action="/account/password">
        <label>New password</label><input name="password" type="password">
        <button type="submit">Update password</button>
      </form>
      <div class="warnbox">No current password is required to change it. Leaving your session open on a shared laptop is dangerous.</div>
    </div>`);
}

function logPage(user, flash) {
  const isSource = user.name === db.config.sourceUsername;
  const rows = db.inAppLog.slice().reverse().map(e => `
    <tr>
      <td class="mono">${esc(e.time)}</td>
      <td>${esc(e.account)}</td>
      <td>${esc(e.event)}</td>
      <td class="mono">${esc(e.device)}</td>
      <td>${isSource ? `<form method="POST" action="/log/delete" style="margin:0"><input type="hidden" name="id" value="${e.id}"><button class="danger" style="margin:0;padding:5px 10px;font-size:12px">delete</button></form>` : ''}</td>
    </tr>`).join('');
  return layout('Log', user, `
    ${flash ? '<div class="card"><b>' + esc(flash) + '</b></div>' : ''}
    <div class="card">
      <h1>Audit log</h1>
      <p class="note">Every login, pass, and change is recorded here.${isSource ? ' As the Source, you can delete entries.' : ''}</p>
      <table><thead><tr><th>Time</th><th>Account</th><th>Event</th><th>Device</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="note">No events yet.</td></tr>'}</tbody></table>
    </div>`);
}

function inboxPage(user, flash) {
  const mine = db.messages.filter(m => m.to === user.name).slice().reverse();
  const list = mine.map(m => `
    <div class="msg">
      <div class="meta">from <b>${esc(m.from)}</b> · ${esc(m.time)}</div>
      <div class="subj">${esc(m.subject) || '(no subject)'}</div>
      <div>${linkify(m.body)}</div>
    </div>`).join('');
  return layout('Inbox', user, `
    ${flash ? '<div class="card"><b>' + esc(flash) + '</b></div>' : ''}
    <div class="card">
      <h1>Inbox</h1>
      <p class="note"><a href="/compose">Compose a message</a> to any player.</p>
      ${list || '<p class="note">No messages.</p>'}
    </div>`);
}
function composePage(user, to) {
  const options = Object.keys(db.users).filter(n => db.users[n].team !== 'admin')
    .map(n => `<option value="${esc(n)}" ${n === to ? 'selected' : ''}>${esc(n)}</option>`).join('');
  return layout('Compose', user, `
    <div class="card">
      <h1>New message</h1>
      <form method="POST" action="/compose">
        <label>To</label><select name="to">${options}</select>
        <label>Subject</label><input name="subject">
        <label>Message</label><input name="body">
        <button type="submit">Send</button>
      </form>
      <div class="warnbox">Links you paste are shown to the recipient as clickable links.</div>
    </div>`);
}
function linkify(s) {
  // Renders http(s) links as clickable — deliberately, so phishing links work.
  return esc(s).replace(/(https?:\/\/[^\s]+)/g, '<a href="$1">$1</a>');
}

// ---------------------------------------------------------------------------
// Instructor (admin) pages — not part of the student attack surface.
// ---------------------------------------------------------------------------
function adminRoutes(req, res, user, p, method) {
  return (async () => {
    if (p === '/' && method === 'GET') return send(res, 200, adminPage(user));
    if (p === '/admin/seed' && method === 'POST') {
      const members = Object.keys(db.users).filter(n => db.users[n].team === db.config.defendingTeam);
      const src = members[Math.floor(Math.random() * members.length)];
      db.config.day = (db.config.day || 0) + 1;
      db.config.sourceUsername = src;
      db.custody = [src];
      save();
      logEvent(src, 'SEED: named today’s Source (day ' + db.config.day + ')', 'admin');
      return redirect(res, '/');
    }
    if (p === '/admin/defending' && method === 'POST') {
      const b = await readBody(req);
      db.config.defendingTeam = b.team === 'red' ? 'red' : 'blue';
      save();
      return redirect(res, '/');
    }
    if (p === '/admin/score' && method === 'POST') {
      const b = await readBody(req);
      const team = b.team === 'red' ? 'red' : 'blue';
      const pts = parseInt(b.points, 10) || 0;
      db.scores[team] += pts;
      db.scoreLog.push({ time: now(), team, points: pts, reason: b.reason || '' });
      save();
      return redirect(res, '/');
    }
    if (p === '/admin/truth' && method === 'GET') {
      let raw = '';
      try { raw = fs.readFileSync(TRUTH_LOG, 'utf8'); } catch (e) {}
      const rows = raw.trim().split('\n').filter(Boolean).reverse().map(l => {
        const e = JSON.parse(l);
        const tamper = /TAMPER/.test(e.event);
        return `<tr style="${tamper ? 'background:rgba(239,68,68,.12)' : ''}"><td class="mono">${esc(e.time)}</td><td>${esc(e.account)}</td><td>${esc(e.event)}</td><td class="mono">${esc(e.device)}</td></tr>`;
      }).join('');
      return send(res, 200, layout('Ground truth', user, `
        <div class="card"><h1>Ground-truth log</h1>
        <p class="note">Append-only. Records everything — including in-app log deletions the players cannot see. This is the authority for scoring.</p>
        <table><thead><tr><th>Time</th><th>Account</th><th>Event</th><th>Device</th></tr></thead><tbody>${rows || '<tr><td colspan=4 class="note">empty</td></tr>'}</tbody></table>
        <a class="btn ghost" href="/">Back</a></div>`));
    }
    return send(res, 404, layout('Not found', user, '<div class="card">404</div>'));
  })();
}
function adminPage(user) {
  const attackers = db.custody.filter(n => db.users[n] && db.users[n].team !== db.config.defendingTeam);
  const custodyRow = db.custody.map(n => {
    const t = db.users[n] ? db.users[n].team : '?';
    const bad = t !== db.config.defendingTeam;
    return `<span class="badge ${bad ? 'red' : 'blue'}" style="margin:2px">${esc(n)}</span>`;
  }).join(' ') || '<span class="note">nobody holds it</span>';
  return layout('Instructor', user, `
    <div class="card">
      <h1>Instructor panel</h1>
      <p class="note">Day ${db.config.day} · defending team: <b>${db.config.defendingTeam}</b> · Source: <b>${esc(db.config.sourceUsername || '—')}</b></p>
      <div class="row">
        <form method="POST" action="/admin/seed"><button type="submit">Start new day (seed Source)</button></form>
        <form method="POST" action="/admin/defending">
          <select name="team"><option value="blue" ${db.config.defendingTeam === 'blue' ? 'selected' : ''}>blue defends</option><option value="red" ${db.config.defendingTeam === 'red' ? 'selected' : ''}>red defends</option></select>
          <button class="ghost" type="submit">Set defender / swap</button>
        </form>
      </div>
    </div>
    <div class="card">
      <h2>Current custody</h2>
      <div>${custodyRow}</div>
      ${attackers.length ? `<div class="warnbox" style="border-color:var(--red);background:rgba(239,68,68,.1)"><b>Infiltration:</b> attacker account(s) hold the secret — ${attackers.map(esc).join(', ')}.</div>` : '<p class="note">No attacker holds the secret.</p>'}
    </div>
    <div class="card">
      <h2>Scoreboard</h2>
      <table><tr><th>Blue</th><th>Red</th></tr><tr><td class="mono" style="font-size:22px">${db.scores.blue}</td><td class="mono" style="font-size:22px">${db.scores.red}</td></tr></table>
      <h2 style="margin-top:16px">Award points</h2>
      <form method="POST" action="/admin/score">
        <div class="row">
          <select name="team"><option value="blue">blue</option><option value="red">red</option></select>
          <input name="points" placeholder="points, e.g. 4 or -1" style="max-width:160px">
        </div>
        <input name="reason" placeholder="reason (e.g. vulnerability discovered +4, patch accepted +2)">
        <button type="submit">Add</button>
      </form>
      ${db.scoreLog.slice().reverse().slice(0, 8).map(s => `<div class="note">${esc(s.time)} · ${esc(s.team)} ${s.points > 0 ? '+' + s.points : s.points} — ${esc(s.reason)}</div>`).join('')}
    </div>
    <div class="card"><h2>Forensics</h2><a class="btn" href="/admin/truth">Open ground-truth log</a></div>
  `);
}

server.listen(PORT, () => console.log('Blind Handoff running at http://localhost:' + PORT));
