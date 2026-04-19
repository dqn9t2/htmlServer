const express = require('express');
const session = require('express-session');
const multer = require('multer');
const AdmZip = require('adm-zip');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const PROJECTS_DIR = path.join(ROOT, 'projects');
const TMP_DIR = path.join(ROOT, 'tmp');
const DB_FILE = path.join(DATA_DIR, 'projects.json');

for (const d of [DATA_DIR, PROJECTS_DIR, TMP_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '{}');

function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return {}; }
}
function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function genCode() {
  // 6-char uppercase alphanumeric, unambiguous
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const db = loadDb();
  while (true) {
    let s = '';
    for (let i = 0; i < 6; i++) s += alphabet[crypto.randomInt(alphabet.length)];
    if (!db[s]) return s;
  }
}
function rmrf(p) {
  if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 200 * 1024 * 1024 } // 200 MB
});

// ---------- Public ----------
const baseCss = `
  body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;color:#222}
  h1{margin-top:0}
  input,button,select{font:inherit;padding:8px 10px;border:1px solid #ccc;border-radius:6px}
  button{background:#2563eb;color:#fff;border-color:#2563eb;cursor:pointer}
  button.danger{background:#dc2626;border-color:#dc2626}
  button.secondary{background:#fff;color:#222}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;vertical-align:middle}
  code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:1.05em}
  form.inline{display:inline}
  .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .muted{color:#666;font-size:.9em}
  .err{color:#b91c1c}
`;

app.get('/', (req, res) => {
  const err = req.query.err ? `<p class="err">${escapeHtml(req.query.err)}</p>` : '';
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Open Project</title><style>${baseCss}</style></head><body>
    <h1>Open a project</h1>
    <p>Enter your project code to view it.</p>
    <form method="get" action="/go">
      <div class="row">
        <input name="code" placeholder="e.g. AB12CD" autofocus required style="text-transform:uppercase">
        <button type="submit">Open</button>
      </div>
    </form>
    ${err}
    <p class="muted"><a href="/admin">Admin</a></p>
  </body></html>`);
});

app.get('/go', (req, res) => {
  const code = String(req.query.code || '').trim().toUpperCase();
  if (!code) return res.redirect('/');
  const db = loadDb();
  if (!db[code]) return res.redirect('/?err=' + encodeURIComponent('Project code not found'));
  res.redirect(`/p/${code}/`);
});

// Serve project files
const INDEX_FILES = ['index.html', 'tour.html'];

app.get('/p/:code/*?', (req, res, next) => {
  const code = req.params.code.toUpperCase();
  const db = loadDb();
  if (!db[code]) return res.status(404).send('Project not found');
  const projDir = path.join(PROJECTS_DIR, code);
  const rel = req.params[0] || '';
  // Prevent path traversal
  const reqTarget = path.normalize(path.join(projDir, rel));
  if (!reqTarget.startsWith(projDir + path.sep) && reqTarget !== projDir) {
    return res.status(403).send('Forbidden');
  }
  // If URL points to a directory (or empty), try index files in order
  const isDirRequest = !rel || rel.endsWith('/') ||
    (fs.existsSync(reqTarget) && fs.statSync(reqTarget).isDirectory());
  if (isDirRequest) {
    for (const name of INDEX_FILES) {
      const idx = path.join(reqTarget, name);
      if (fs.existsSync(idx)) return res.sendFile(idx);
    }
    return res.status(404).send('No index.html or tour.html found');
  }
  if (!fs.existsSync(reqTarget)) return res.status(404).send('File not found');
  res.sendFile(reqTarget);
});

// ---------- Admin ----------
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  const err = req.query.err ? `<p class="err">${escapeHtml(req.query.err)}</p>` : '';
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title><style>${baseCss}</style></head><body>
    <h1>Admin login</h1>
    <form method="post" action="/admin/login">
      <div class="row">
        <input type="password" name="password" placeholder="Password" autofocus required>
        <button type="submit">Sign in</button>
      </div>
    </form>
    ${err}
  </body></html>`);
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    req.session.admin = true;
    return res.redirect('/admin');
  }
  res.redirect('/admin/login?err=' + encodeURIComponent('Wrong password'));
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin', requireAdmin, (req, res) => {
  const db = loadDb();
  const msg = req.query.msg ? `<p class="muted">${escapeHtml(req.query.msg)}</p>` : '';
  const err = req.query.err ? `<p class="err">${escapeHtml(req.query.err)}</p>` : '';
  const rows = Object.entries(db)
    .sort((a, b) => (b[1].createdAt || 0) - (a[1].createdAt || 0))
    .map(([code, p]) => {
      const hasFiles = fs.existsSync(path.join(PROJECTS_DIR, code));
      return `<tr>
        <td><strong>${escapeHtml(p.name)}</strong></td>
        <td><code>${code}</code> <a href="/p/${code}/" target="_blank">open</a></td>
        <td>${hasFiles ? 'yes' : '<span class="err">missing</span>'}</td>
        <td>
          <form class="inline" method="post" action="/admin/rename">
            <input type="hidden" name="code" value="${code}">
            <input name="name" value="${escapeHtml(p.name)}" required>
            <button type="submit" class="secondary">Rename</button>
          </form>
          <form class="inline" method="post" action="/admin/upload" enctype="multipart/form-data">
            <input type="hidden" name="code" value="${code}">
            <input type="file" name="zip" accept=".zip" required>
            <button type="submit" class="secondary">Upload zip</button>
          </form>
          <form class="inline" method="post" action="/admin/delete" onsubmit="return confirm('Delete project ${escapeHtml(p.name)}?')">
            <input type="hidden" name="code" value="${code}">
            <button type="submit" class="danger">Delete</button>
          </form>
        </td>
      </tr>`;
    }).join('');

  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Admin</title><style>${baseCss}</style></head><body>
    <div class="row" style="justify-content:space-between">
      <h1>Projects</h1>
      <form method="post" action="/admin/logout"><button class="secondary">Log out</button></form>
    </div>
    ${msg}${err}
    <h2>Create new project</h2>
    <form method="post" action="/admin/create" enctype="multipart/form-data">
      <div class="row">
        <input name="name" placeholder="Project name" required>
        <input type="file" name="zip" accept=".zip">
        <button type="submit">Create</button>
      </div>
      <p class="muted">Zip is optional — you can upload it later. The zip should contain an <code>index.html</code> at the root (or inside a single folder).</p>
    </form>
    <h2>Existing</h2>
    ${Object.keys(db).length === 0 ? '<p class="muted">No projects yet.</p>' : `<table>
      <thead><tr><th>Name</th><th>Code</th><th>Files</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`}
  </body></html>`);
});

function extractZipToProject(zipPath, code) {
  const projDir = path.join(PROJECTS_DIR, code);
  rmrf(projDir);
  fs.mkdirSync(projDir, { recursive: true });
  const zip = new AdmZip(zipPath);
  zip.extractAllTo(projDir, true);
  // If everything is inside a single top-level folder, flatten it
  const entries = fs.readdirSync(projDir);
  if (entries.length === 1) {
    const only = path.join(projDir, entries[0]);
    if (fs.statSync(only).isDirectory()) {
      for (const f of fs.readdirSync(only)) {
        fs.renameSync(path.join(only, f), path.join(projDir, f));
      }
      fs.rmdirSync(only);
    }
  }
}

app.post('/admin/create', requireAdmin, upload.single('zip'), (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) {
    if (req.file) rmrf(req.file.path);
    return res.redirect('/admin?err=' + encodeURIComponent('Name required'));
  }
  const code = genCode();
  const db = loadDb();
  db[code] = { name, createdAt: Date.now() };
  saveDb(db);
  if (req.file) {
    try { extractZipToProject(req.file.path, code); }
    catch (e) {
      delete db[code]; saveDb(db);
      return res.redirect('/admin?err=' + encodeURIComponent('Zip extract failed: ' + e.message));
    }
    finally { rmrf(req.file.path); }
  }
  res.redirect('/admin?msg=' + encodeURIComponent(`Created "${name}" with code ${code}`));
});

app.post('/admin/upload', requireAdmin, upload.single('zip'), (req, res) => {
  const code = String(req.body.code || '').toUpperCase();
  const db = loadDb();
  if (!db[code]) {
    if (req.file) rmrf(req.file.path);
    return res.redirect('/admin?err=' + encodeURIComponent('Project not found'));
  }
  if (!req.file) return res.redirect('/admin?err=' + encodeURIComponent('No file'));
  try { extractZipToProject(req.file.path, code); }
  catch (e) { return res.redirect('/admin?err=' + encodeURIComponent('Zip extract failed: ' + e.message)); }
  finally { rmrf(req.file.path); }
  res.redirect('/admin?msg=' + encodeURIComponent(`Uploaded to ${code}`));
});

app.post('/admin/rename', requireAdmin, (req, res) => {
  const code = String(req.body.code || '').toUpperCase();
  const name = String(req.body.name || '').trim();
  const db = loadDb();
  if (!db[code]) return res.redirect('/admin?err=' + encodeURIComponent('Not found'));
  if (!name) return res.redirect('/admin?err=' + encodeURIComponent('Name required'));
  db[code].name = name;
  saveDb(db);
  res.redirect('/admin?msg=' + encodeURIComponent('Renamed'));
});

app.post('/admin/delete', requireAdmin, (req, res) => {
  const code = String(req.body.code || '').toUpperCase();
  const db = loadDb();
  if (!db[code]) return res.redirect('/admin?err=' + encodeURIComponent('Not found'));
  delete db[code];
  saveDb(db);
  rmrf(path.join(PROJECTS_DIR, code));
  res.redirect('/admin?msg=' + encodeURIComponent('Deleted'));
});

app.listen(PORT, () => {
  console.log(`htmlServer listening on http://localhost:${PORT}`);
  console.log(`Admin password: ${ADMIN_PASSWORD === 'admin' ? '"admin" (CHANGE via ADMIN_PASSWORD env var)' : '(set)'}`);
});
