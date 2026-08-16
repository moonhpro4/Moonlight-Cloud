require('dotenv').config();
const express = require('express');
const multer  = require('multer');
const { v4: uuidv4 } = require('uuid');
const { nanoid } = require('nanoid');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');
const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');
const store = require('./db');

const app    = express();
const gClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads', { recursive: true });

// File metadata, sessions, and the keep-forever preference now live in
// SQLite (./db.js) instead of plain JS objects, so they survive server
// restarts/redeploys and stay consistent no matter which device you're on.
// (Note: uploaded file *bytes* under uploads/, and the moonlight.db file
// itself, are only truly durable if DATA_DIR points at a Railway Volume —
// otherwise both still reset on redeploy, same as before.)

const activeDownloads = new Set();

// ── MCP (Model Context Protocol) connector state ────────────────────────────
// Short-lived OAuth handshake state — fine to keep in memory, codes/flows
// expire within minutes regardless.
const mcpClients    = {};
const mcpAuthFlows  = {};
const mcpAuthCodes  = {};
const mcpTokens     = {};

const MAX_CONCURRENT_DL = 2;
const GB = 1024 * 1024 * 1024;
const USER_MAX_SIZE     = 9 * 1024 * GB; // signed in: 9 TB free total
const GUEST_FILE_CAP    = 5 * GB;        // guest: 5 GB per file, no total cap
const DAYS_7  = 7  * 24 * 60 * 60 * 1000;  // guest files: fixed 7-day, unrecoverable expiry
const DAYS_30 = 30 * 24 * 60 * 60 * 1000;  // signed-in files: 30-day default, or keep-forever

// ── Dynamic base URL from request ────────────────────────────────────────────
function getBase(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host  = req.headers['x-forwarded-host']  || req.headers['host'] || req.get('host');
  return `${proto}://${host}`;
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ── Auto-delete job: runs every hour ─────────────────────────────────────────
// Guest files are never keep-forever-able (enforced below) and always use the
// 7-day expiry, so this permanently and irrecoverably deletes them on
// schedule — no recovery even if the uploader signs in later.
setInterval(() => {
  const now = Date.now();
  store.allFiles().forEach(f => {
    if (!f.keepForever && f.expiresAt && new Date(f.expiresAt).getTime() < now) {
      try { fs.unlinkSync(f.filepath); } catch {}
      store.deleteFileRow(f.id);
    }
  });
}, 60 * 60 * 1000);

// ── Auth helpers ──────────────────────────────────────────────────────────────
function getSession(req) {
  const t = req.headers['x-session-token'];
  return t ? store.getSessionRow(t) : null;
}

function getQuota(session, ip) {
  if (session) {
    const mine = store.filesByOwner(session.userId);
    const used = mine.reduce((a, f) => a + f.size, 0);
    return { used, max: USER_MAX_SIZE, count: mine.length, maxFiles: Infinity, isGuest: false };
  }
  // Guests: no total/account cap at all — only a per-file size limit,
  // enforced separately at upload time (GUEST_FILE_CAP).
  return { used: 0, max: Infinity, count: 0, maxFiles: Infinity, isGuest: true };
}

// ── Multer ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename:    (req, file, cb) => { const id = uuidv4(); req.fileId = id; cb(null, id + path.extname(file.originalname)); }
});
const upload = multer({ storage }); // no global size limit — enforced per-tier below

// Reject oversized guest uploads early, before the body is even read, using
// the declared Content-Length (browsers always send this for file uploads).
function guestSizeGate(req, res, next) {
  const session = getSession(req);
  if (session) return next();
  const len = parseInt(req.headers['content-length'] || '0', 10);
  if (len > GUEST_FILE_CAP + 1_000_000) { // small slack for multipart overhead
    return res.status(413).json({ ok:false, error:'Guests can upload up to 5GB per file. Sign in for 9TB total storage.' });
  }
  next();
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────
app.post('/api/malware-check', async (req, res) => {
  // Cosmetic step only — we do not scan or block uploads. See download page
  // disclaimer: users are told plainly that files are not scanned.
  res.json({ clean: true });
});

// ── Google auth ───────────────────────────────────────────────────────────────
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket  = await gClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const token   = uuidv4();
    store.setSessionRow(token, { userId: payload.sub, email: payload.email, name: payload.name, picture: payload.picture });
    res.json({ ok:true, token, name:payload.name, email:payload.email, picture:payload.picture,
      keepForever: store.getUserKeepForever(payload.sub) });
  } catch { res.status(401).json({ ok:false, error:'Invalid token' }); }
});

app.post('/api/auth/logout', (req, res) => {
  const t = req.headers['x-session-token'];
  if (t) store.deleteSessionRow(t);
  res.json({ ok:true });
});

// ═══════════════════════════════════════════════════════════════════════════
// MCP connector — lets Claude / ChatGPT search a user's Moonlight Cloud files
// ═══════════════════════════════════════════════════════════════════════════
function b64url(buf) { return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = getBase(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/mcp/authorize`,
    token_endpoint: `${base}/mcp/token`,
    registration_endpoint: `${base}/mcp/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none']
  });
});
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const base = getBase(req);
  res.json({ resource: `${base}/mcp`, authorization_servers: [base] });
});

app.post('/mcp/register', (req, res) => {
  const clientId = uuidv4();
  mcpClients[clientId] = {
    redirect_uris: req.body.redirect_uris || [],
    client_name: req.body.client_name || 'MCP Client'
  };
  res.status(201).json({
    client_id: clientId,
    redirect_uris: mcpClients[clientId].redirect_uris,
    client_name: mcpClients[clientId].client_name,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code']
  });
});

app.get('/mcp/authorize', (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;
  if (!redirect_uri) return res.status(400).send('Missing redirect_uri');
  const flow = uuidv4();
  mcpAuthFlows[flow] = { client_id, redirect_uri, state, code_challenge, code_challenge_method };
  res.redirect(`/mcplogon?flow=${flow}`);
});

app.get('/mcplogon', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mcplogon.html')));

app.post('/mcp/authorize/complete', async (req, res) => {
  const { flow, credential } = req.body;
  const pending = mcpAuthFlows[flow];
  if (!pending) return res.status(400).json({ ok:false, error:'Sign-in link expired, please try connecting again.' });
  try {
    const ticket  = await gClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const code = uuidv4();
    mcpAuthCodes[code] = {
      userId: payload.sub, name: payload.name, email: payload.email,
      redirect_uri: pending.redirect_uri, code_challenge: pending.code_challenge,
      expires: Date.now() + 5*60*1000
    };
    delete mcpAuthFlows[flow];
    const redirect = new URL(pending.redirect_uri);
    redirect.searchParams.set('code', code);
    if (pending.state) redirect.searchParams.set('state', pending.state);
    res.json({ ok:true, redirect: redirect.toString(), name: payload.name });
  } catch {
    res.status(401).json({ ok:false, error:'Google sign-in failed.' });
  }
});

app.post('/mcp/token', (req, res) => {
  const { code, code_verifier } = req.body;
  const entry = mcpAuthCodes[code];
  if (!entry || entry.expires < Date.now()) return res.status(400).json({ error: 'invalid_grant' });
  if (entry.code_challenge) {
    const computed = b64url(crypto.createHash('sha256').update(code_verifier || '').digest());
    if (computed !== entry.code_challenge) return res.status(400).json({ error: 'invalid_grant' });
  }
  const accessToken = crypto.randomBytes(32).toString('hex');
  mcpTokens[accessToken] = { userId: entry.userId, name: entry.name, email: entry.email };
  delete mcpAuthCodes[code];
  res.json({ access_token: accessToken, token_type: 'Bearer' });
});

function getMcpUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token ? mcpTokens[token] : null;
}

app.post('/mcp', express.json(), async (req, res) => {
  const user = getMcpUser(req);
  const { id, method, params } = req.body || {};

  if (!user && method !== 'initialize') {
    return res.status(401).json({ jsonrpc:'2.0', id, error:{ code:-32001, message:'Unauthorized' } });
  }
  if (method === 'initialize') {
    return res.json({ jsonrpc:'2.0', id, result:{
      protocolVersion: '2024-11-05', capabilities: { tools: {} },
      serverInfo: { name: 'moonlight-cloud', version: '1.0.0' }
    }});
  }
  if (method === 'notifications/initialized') return res.status(202).end();

  if (method === 'tools/list') {
    return res.json({ jsonrpc:'2.0', id, result:{
      tools: [{
        name: 'search_files',
        description: "Search the signed-in user's Moonlight Cloud files by name (e.g. \"find the photo of the mountain\", \"my resume pdf\"). Returns matching files with their share links.",
        inputSchema: { type:'object', properties:{ query:{ type:'string', description:'Search text to match against file names' } }, required:['query'] }
      }]
    }});
  }
  if (method === 'tools/call' && params?.name === 'search_files') {
    const query = (params.arguments?.query || '').toLowerCase();
    const matches = store.filesByOwner(user.userId)
      .filter(f => !query || f.name.toLowerCase().includes(query))
      .slice(0, 20)
      .map(f => ({ name: f.name, size: f.size, uploadedAt: f.uploadedAt, shareUrl: f.shareUrl }));
    const text = matches.length
      ? matches.map(m => `• ${m.name} (${(m.size/1e6).toFixed(1)} MB) — ${m.shareUrl}`).join('\n')
      : 'No files matched that search.';
    return res.json({ jsonrpc:'2.0', id, result:{ content:[{ type:'text', text }] } });
  }
  res.status(400).json({ jsonrpc:'2.0', id, error:{ code:-32601, message:'Method not found' } });
});

// ── Keep forever setting ──────────────────────────────────────────────────────
// Guest uploads can NEVER be kept forever — this requires a real session.
app.post('/api/settings/keep-forever', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok:false, error:'Sign in required.' });
  store.setUserKeepForever(session.userId, true);
  store.setAllKeepForeverForOwner(session.userId);
  res.json({ ok:true });
});

app.get('/api/settings', (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ keepForever: false });
  res.json({ keepForever: store.getUserKeepForever(session.userId) });
});

// ── Quota ─────────────────────────────────────────────────────────────────────
app.get('/api/quota', (req, res) => res.json(getQuota(getSession(req), req.ip)));

// ── Shared upload-finalize logic (used by both direct upload and by-URL) ────
function finalizeUpload({ req, filePath, originalname, size, mimetype, hash }, cb) {
  const session = getSession(req);

  if (!session && size > GUEST_FILE_CAP) {
    try { fs.unlinkSync(filePath); } catch {}
    return cb({ status:413, error:'Guests can upload up to 5GB per file. Sign in for 9TB total storage.' });
  }
  if (session) {
    const quota = getQuota(session, req.ip);
    if (quota.used + size > quota.max) {
      try { fs.unlinkSync(filePath); } catch {}
      return cb({ status:403, error:'You\'re out of storage. Delete some files, or create a new account for another free 9TB.' });
    }
  }

  const fileId   = uuidv4();
  const shareId  = nanoid(8);
  const base     = getBase(req);
  const shareUrl = `${base}/d/${shareId}`;
  const rawUrl   = `${base}/download/${fileId}/raw`;
  const keepForever = session ? store.getUserKeepForever(session.userId) : false;
  const expiresAt = keepForever ? null
    : new Date(Date.now() + (session ? DAYS_30 : DAYS_7)).toISOString();

  const finalPath = path.join('uploads', fileId + path.extname(originalname));
  fs.renameSync(filePath, finalPath);

  store.insertFile({
    id: fileId, shareId, name: originalname, size, mimetype, hash: hash || null,
    owner: session ? session.name : 'Guest',
    ownerId: session ? session.userId : req.ip,
    uploadedAt: new Date().toISOString(),
    filepath: finalPath, shareUrl, keepForever, expiresAt,
    isGuest: !session
  });

  const commands = {
    windows: `Invoke-WebRequest -Uri "${rawUrl}" -OutFile "${originalname}"`,
    mac:     `curl -L "${rawUrl}" -o "${originalname}"`,
    linux:   `wget -O "${originalname}" "${rawUrl}"`
  };
  cb(null, { fileId, shareId, name: originalname, size, shareUrl, rawUrl, commands, keepForever, expiresAt });
}

// ── Upload ────────────────────────────────────────────────────────────────────
app.post('/api/upload', guestSizeGate, (req, res) => {
  upload.single('file')(req, res, err => {
    if (err) return res.status(400).json({ ok:false, error: err.message });
    if (!req.file) return res.status(400).json({ ok:false, error:'No file received' });
    finalizeUpload({
      req, filePath: req.file.path, originalname: req.file.originalname,
      size: req.file.size, mimetype: req.file.mimetype, hash: req.body.hash
    }, (err, result) => {
      if (err) return res.status(err.status).json({ ok:false, error: err.error });
      res.json({ ok:true, ...result });
    });
  });
});

// ── Download by URL ───────────────────────────────────────────────────────────
// Fetches a direct file link server-side and drops it straight into the
// user's cloud storage — nothing touches the requester's device.
app.post('/api/upload-from-url', async (req, res) => {
  const { url } = req.body || {};
  if (!url || !/^https?:\/\//i.test(url)) return res.status(400).json({ ok:false, error:'Please provide a valid http(s) URL.' });

  const session = getSession(req);
  const cap = session ? getQuota(session, req.ip).max - getQuota(session, req.ip).used : GUEST_FILE_CAP;

  let upstream;
  try {
    upstream = await fetch(url, { redirect: 'follow' });
  } catch {
    return res.status(400).json({ ok:false, error:'Could not reach that URL.' });
  }
  if (!upstream.ok || !upstream.body) {
    return res.status(400).json({ ok:false, error:`That URL returned an error (${upstream.status}).` });
  }

  const declaredLen = parseInt(upstream.headers.get('content-length') || '0', 10);
  if (declaredLen && declaredLen > cap) {
    return res.status(413).json({ ok:false, error: session ? 'That file is larger than your remaining storage.' : 'Guests can upload up to 5GB per file. Sign in for 9TB total storage.' });
  }

  let originalname = 'download';
  try {
    const u = new URL(url);
    originalname = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || 'download');
  } catch {}
  const disposition = upstream.headers.get('content-disposition');
  const m = disposition && disposition.match(/filename="?([^";]+)"?/i);
  if (m) originalname = m[1];

  const tmpId = uuidv4();
  const tmpPath = path.join('uploads', 'tmp-' + tmpId);
  const writeStream = fs.createWriteStream(tmpPath);
  let bytesWritten = 0;
  let aborted = false;

  const reader = upstream.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesWritten += value.length;
      if (bytesWritten > cap) {
        aborted = true;
        try { reader.cancel(); } catch {}
        break;
      }
      writeStream.write(Buffer.from(value));
    }
  } catch {
    aborted = true;
  }
  writeStream.end();

  if (aborted) {
    try { fs.unlinkSync(tmpPath); } catch {}
    return res.status(413).json({ ok:false, error: session ? 'That file is larger than your remaining storage.' : 'Guests can upload up to 5GB per file. Sign in for 9TB total storage.' });
  }

  finalizeUpload({
    req, filePath: tmpPath, originalname, size: bytesWritten,
    mimetype: upstream.headers.get('content-type') || 'application/octet-stream'
  }, (err, result) => {
    if (err) return res.status(err.status).json({ ok:false, error: err.error });
    res.json({ ok:true, ...result });
  });
});

// ── Keep forever for specific file ───────────────────────────────────────────
// Requires a real session — guest files can never be marked keep-forever.
app.post('/api/file/:fileId/keep-forever', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(403).json({ ok:false, error:'Sign in required.' });
  const file = store.getFile(req.params.fileId);
  if (!file) return res.status(404).json({ ok:false });
  if (file.ownerId !== session.userId) return res.status(403).json({ ok:false });
  store.updateFile(file.id, { keepForever: true, expiresAt: null });
  res.json({ ok:true });
});

// ── Share page ────────────────────────────────────────────────────────────────
app.get('/api/share/:shareId', (req, res) => {
  const file = store.getFileByShare(req.params.shareId);
  if (!file) return res.status(404).json({ ok:false, error:'Not found' });
  const base   = getBase(req);
  const rawUrl = `${base}/download/${file.id}/raw`;
  const busy   = activeDownloads.size >= MAX_CONCURRENT_DL && !activeDownloads.has(req.params.shareId);
  const commands = {
    windows: `Invoke-WebRequest -Uri "${rawUrl}" -OutFile "${file.name}"`,
    mac:     `curl -L "${rawUrl}" -o "${file.name}"`,
    linux:   `wget -O "${file.name}" "${rawUrl}"`
  };
  res.json({ ok:true, fileId:file.id, name:file.name, size:file.size,
    uploadedAt:file.uploadedAt, magnetLink:file.magnetLink, webSeedUrl:rawUrl,
    busy, commands, keepForever:file.keepForever, expiresAt:file.expiresAt });
});

app.post('/api/dl-start/:shareId', (req, res) => {
  if (activeDownloads.size >= MAX_CONCURRENT_DL && !activeDownloads.has(req.params.shareId))
    return res.json({ ok:false, busy:true });
  activeDownloads.add(req.params.shareId);
  res.json({ ok:true });
});
app.post('/api/dl-end/:shareId', (req, res) => { activeDownloads.delete(req.params.shareId); res.json({ ok:true }); });

// ── My files ──────────────────────────────────────────────────────────────────
app.get('/api/my-files', (req, res) => {
  const session = getSession(req);
  const mine = session ? store.filesByOwner(session.userId) : store.filesByOwner(req.ip);
  res.json({ ok:true, files: mine.map(f => ({ id:f.id, shareId:f.shareId, shareUrl:f.shareUrl, name:f.name,
    size:f.size, uploadedAt:f.uploadedAt, keepForever:f.keepForever, expiresAt:f.expiresAt })) });
});

app.get('/api/file/:fileId', (req, res) => {
  const file = store.getFile(req.params.fileId);
  if (!file) return res.status(404).json({ ok:false, error:'Not found' });
  const base   = getBase(req);
  const rawUrl = `${base}/download/${file.id}/raw`;
  res.json({ ok:true, name:file.name, size:file.size, uploadedAt:file.uploadedAt,
    keepForever:file.keepForever, expiresAt:file.expiresAt,
    commands:{ windows:`Invoke-WebRequest -Uri "${rawUrl}" -OutFile "${file.name}"`,
      mac:`curl -L "${rawUrl}" -o "${file.name}"`, linux:`wget -O "${file.name}" "${rawUrl}"` }
  });
});

app.delete('/api/file/:fileId', (req, res) => {
  const session = getSession(req);
  const file    = store.getFile(req.params.fileId);
  if (!file) return res.status(404).json({ ok:false, error:'Not found' });
  const ownerId = session ? session.userId : req.ip;
  if (file.ownerId !== ownerId) return res.status(403).json({ ok:false, error:'Not your file' });
  try { fs.unlinkSync(file.filepath); } catch {}
  store.deleteFileRow(file.id);
  res.json({ ok:true });
});

app.get('/download/:fileId/raw', (req, res) => {
  const file = store.getFile(req.params.fileId);
  if (!file) return res.status(404).send('Not found');
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
  res.setHeader('Content-Length', file.size);
  res.setHeader('Accept-Ranges', 'bytes');
  fs.createReadStream(file.filepath).pipe(res);
});

app.get('/d/:shareId', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));

// Direct link — zero UI, no download page, no confirmation. Hitting this URL
// starts the browser's download immediately.
app.get('/d/:shareId/direct', (req, res) => {
  const file = store.getFileByShare(req.params.shareId);
  if (!file) return res.status(404).send('Not found');
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
  res.setHeader('Content-Length', file.size);
  res.setHeader('Accept-Ranges', 'bytes');
  fs.createReadStream(file.filepath).pipe(res);
});
app.get('/download/:fileId', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));

// ── Mobile app (Android WebView shell) ─────────────────────────────────────────
app.get('/mobile', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/mobilelogin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mobilelogin.html')));

// ═══════════════════════════════════════════════════════════════════════════
// Moonlight AI — chat assistant. The API token lives only in this server's
// environment (MOONLIGHT_AI_TOKEN) and is never sent to the browser; the
// client only ever talks to our own /api/ai/* routes.
// ═══════════════════════════════════════════════════════════════════════════
const AI_API_URL = process.env.MOONLIGHT_AI_API_URL;
const AI_TOKEN    = process.env.MOONLIGHT_AI_TOKEN;

// Real warmup call — the underlying model endpoint can have a cold start, so
// this is an actual first round-trip to the API (not a cosmetic delay) that
// the client waits on before enabling the chat input.
app.get('/api/ai/warmup', async (req, res) => {
  if (!AI_API_URL || !AI_TOKEN) return res.status(503).json({ ok:false, error:'AI is not configured on this server yet.' });
  try {
    const r = await fetch(AI_API_URL, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${AI_TOKEN}` },
      body: JSON.stringify({ messages: [{ role:'system', content:'ping' }] })
    });
    res.json({ ok: true, warm: r.status < 500 });
  } catch {
    res.status(503).json({ ok:false, error:'Could not reach the AI service.' });
  }
});

app.get('/api/ai/conversations', (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ ok:true, conversations: [] }); // guests: not persisted
  res.json({ ok:true, conversations: store.listConversations(session.userId) });
});

app.get('/api/ai/conversations/:id', (req, res) => {
  const session = getSession(req);
  const convo = store.getConversation(req.params.id);
  if (!convo || !session || convo.userId !== session.userId) return res.status(404).json({ ok:false, error:'Not found' });
  res.json({ ok:true, messages: store.getMessages(convo.id) });
});

app.delete('/api/ai/conversations/:id', (req, res) => {
  const session = getSession(req);
  const convo = store.getConversation(req.params.id);
  if (!convo || !session || convo.userId !== session.userId) return res.status(404).json({ ok:false, error:'Not found' });
  store.deleteConversation(convo.id);
  res.json({ ok:true });
});

app.post('/api/ai/chat', async (req, res) => {
  if (!AI_API_URL || !AI_TOKEN) return res.status(503).json({ ok:false, error:'AI is not configured on this server yet.' });
  const session = getSession(req);
  const { message, conversationId } = req.body || {};
  if (!message || !message.trim()) return res.status(400).json({ ok:false, error:'Empty message.' });

  let convoId = conversationId;
  let history = [];
  if (session) {
    if (convoId) {
      const convo = store.getConversation(convoId);
      if (!convo || convo.userId !== session.userId) return res.status(404).json({ ok:false, error:'Conversation not found' });
      history = store.getMessages(convoId).map(m => ({ role:m.role, content:m.content }));
    } else {
      convoId = store.createConversation(session.userId, message.trim().slice(0, 60));
    }
    store.addMessage(convoId, 'user', message);
  }

  try {
    const r = await fetch(AI_API_URL, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${AI_TOKEN}` },
      body: JSON.stringify({ messages: [...history, { role:'user', content: message }] })
    });
    const rawText = await r.text();
    let data = {};
    try { data = JSON.parse(rawText); } catch { data = rawText; }

    // Best-effort extraction across common response shapes. If none match,
    // surface the actual raw response in the error instead of guessing
    // silently — that's what lets us pin down the real shape and fix this
    // in one line once we see it.
    const reply = (typeof data === 'object' && data !== null) ? (
      data.reply || data.message?.content || data.message || data.content || data.text || data.output
      || data.choices?.[0]?.message?.content || data.choices?.[0]?.text
      || data.candidates?.[0]?.content?.parts?.[0]?.text // Gemini-native shape
      || data.response
      || null
    ) : (typeof data === 'string' && data.trim() ? data : null);

    if (!reply) {
      console.error('Unrecognized AI response shape:', JSON.stringify(data).slice(0, 500));
      return res.status(502).json({ ok:false, error:'Unexpected response from AI service.', debug: typeof data === 'string' ? data.slice(0,300) : data });
    }

    if (session) store.addMessage(convoId, 'assistant', reply);
    res.json({ ok:true, reply, conversationId: convoId || null });
  } catch (e) {
    res.status(502).json({ ok:false, error:'Could not reach the AI service.', debug: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🌙 Moonlight Cloud on port ${PORT}`));
