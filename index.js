require('dotenv').config();
const express = require('express');
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

// ── Chunked, resumable uploads ────────────────────────────────────────────────
// Files are sent in 8MB pieces instead of one giant request. If the network
// drops or (on the Android app) the OS kills the app mid-upload, the client
// resumes from the last completed piece — the server just needs to remember
// which chunks it already has for a given uploadId, which chunkDir does.
const UPLOAD_CHUNK_SIZE = 8 * 1024 * 1024;
const CHUNK_ROOT = 'uploads/chunks';
if (!fs.existsSync(CHUNK_ROOT)) fs.mkdirSync(CHUNK_ROOT, { recursive: true });
const uploadSessions = {}; // uploadId -> { chunkDir, originalname, mimetype, totalSize, hash, receivedChunks:Set, createdAt }

// Abandoned upload sessions (browser closed and never resumed) get swept up
// alongside the hourly expired-file cleanup job.
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of Object.entries(uploadSessions)) {
    if (now - s.createdAt > 24 * 60 * 60 * 1000) {
      try { fs.rmSync(s.chunkDir, { recursive:true, force:true }); } catch {}
      delete uploadSessions[id];
    }
  }
}, 60 * 60 * 1000);

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

// Direct sign-in from the /mcp landing page's "Get MCP" button (no Claude
// involved yet) — a plain Google login that then hands the user off to
// /mcpcustom to see/copy their personal MCP URL.
app.post('/mcp/direct-login', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket  = await gClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const token = uuidv4();
    store.setSessionRow(token, { userId: payload.sub, email: payload.email, name: payload.name, picture: payload.picture });
    res.json({ ok:true, token });
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

// GET /mcp is what a human sees browsing here directly — a landing page
// explaining the connector, with a "Get MCP" button.
app.get('/mcp', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mcp-landing.html')));
app.get('/mcpcustom', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mcpcustom.html')));

// Personal, permanent MCP URL — created on first request, regeneratable.
app.get('/api/mcp/my-url', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok:false, error:'Sign in required.' });
  const token = store.getOrCreateMcpToken(session.userId);
  res.json({ ok:true, url: `${getBase(req)}/mcp/u/${token}`, name: session.name, email: session.email });
});
app.post('/api/mcp/regenerate', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok:false, error:'Sign in required.' });
  const token = store.regenerateMcpToken(session.userId);
  res.json({ ok:true, url: `${getBase(req)}/mcp/u/${token}` });
});

// Shared JSON-RPC handler for both connection methods: the OAuth-driven flow
// (Claude connects to plain /mcp, does its own Google-login redirect) and the
// permanent personal URL (/mcp/u/<token> — auth is the URL itself, no login
// step inside the AI client at all).
async function handleMcpRequest(user, body, res) {
  const { id, method, params } = body || {};

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
}

app.post('/mcp', express.json(), (req, res) => handleMcpRequest(getMcpUser(req), req.body, res));

// Personal permanent-URL endpoint — the token in the path IS the credential.
app.post('/mcp/u/:token', express.json(), (req, res) => {
  const userId = store.getUserIdByMcpToken(req.params.token);
  handleMcpRequest(userId ? { userId } : null, req.body, res);
});
app.get('/mcp/u/:token', (req, res) => {
  res.status(405).set('Allow', 'POST').json({ error: 'Method Not Allowed — this MCP server only accepts POST JSON-RPC requests.' });
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

// ── Chunked upload: init / chunk / status / complete ─────────────────────────
app.post('/api/upload/init', express.json(), (req, res) => {
  const session = getSession(req);
  const { name, size, mimetype, hash } = req.body || {};
  if (!name || !size) return res.status(400).json({ ok:false, error:'Missing file info.' });

  if (!session && size > GUEST_FILE_CAP) {
    return res.status(413).json({ ok:false, error:'Guests can upload up to 5GB per file. Sign in for 9TB total storage.' });
  }
  if (session) {
    const quota = getQuota(session, req.ip);
    if (quota.used + size > quota.max) {
      return res.status(403).json({ ok:false, error:'You\'re out of storage. Delete some files, or create a new account for another free 9TB.' });
    }
  }

  const uploadId = uuidv4();
  const chunkDir = path.join(CHUNK_ROOT, uploadId);
  fs.mkdirSync(chunkDir, { recursive: true });
  uploadSessions[uploadId] = {
    chunkDir, originalname: name, mimetype: mimetype || 'application/octet-stream',
    totalSize: size, hash: hash || null, receivedChunks: new Set(), createdAt: Date.now()
  };
  res.json({ ok:true, uploadId, chunkSize: UPLOAD_CHUNK_SIZE });
});

app.post('/api/upload/chunk/:uploadId', (req, res) => {
  const s = uploadSessions[req.params.uploadId];
  if (!s) return res.status(404).json({ ok:false, error:'Upload session not found — please restart the upload.' });
  const index = parseInt(req.query.index, 10);
  if (isNaN(index)) return res.status(400).json({ ok:false, error:'Missing chunk index.' });

  const chunkPath = path.join(s.chunkDir, String(index));
  const writeStream = fs.createWriteStream(chunkPath);
  req.pipe(writeStream);
  req.on('error', () => { try { res.status(500).json({ ok:false, error:'Upload interrupted.' }); } catch {} });
  writeStream.on('finish', () => { s.receivedChunks.add(index); res.json({ ok:true, received: index }); });
  writeStream.on('error', () => res.status(500).json({ ok:false, error:'Failed to save chunk.' }));
});

app.get('/api/upload/status/:uploadId', (req, res) => {
  const s = uploadSessions[req.params.uploadId];
  if (!s) return res.status(404).json({ ok:false, error:'Upload session not found.' });
  res.json({ ok:true, receivedChunks: Array.from(s.receivedChunks), totalSize: s.totalSize });
});

app.post('/api/upload/complete/:uploadId', async (req, res) => {
  const s = uploadSessions[req.params.uploadId];
  if (!s) return res.status(404).json({ ok:false, error:'Upload session not found.' });

  const totalChunks = Math.ceil(s.totalSize / UPLOAD_CHUNK_SIZE);
  for (let i = 0; i < totalChunks; i++) {
    if (!s.receivedChunks.has(i)) return res.status(400).json({ ok:false, error:`Missing chunk ${i} — upload incomplete.` });
  }

  const tmpPath = path.join('uploads', 'tmp-' + req.params.uploadId);
  await new Promise((resolve, reject) => {
    const writeStream = fs.createWriteStream(tmpPath);
    writeStream.on('finish', resolve);
    writeStream.on('error', reject);
    (async () => {
      for (let i = 0; i < totalChunks; i++) {
        const data = fs.readFileSync(path.join(s.chunkDir, String(i)));
        writeStream.write(data);
      }
      writeStream.end();
    })();
  });
  try { fs.rmSync(s.chunkDir, { recursive:true, force:true }); } catch {}

  finalizeUpload({
    req, filePath: tmpPath, originalname: s.originalname,
    size: s.totalSize, mimetype: s.mimetype, hash: s.hash
  }, (err, result) => {
    delete uploadSessions[req.params.uploadId];
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
// client only ever talks to our own /api/ai/* routes. Uses the official
// OpenAI SDK against the OpenAI-compatible endpoint — no guessed request or
// response shape.
// ═══════════════════════════════════════════════════════════════════════════
const OpenAI = require('openai');
const AI_API_URL = process.env.MOONLIGHT_AI_API_URL;
const AI_TOKEN    = process.env.MOONLIGHT_AI_TOKEN;
const AI_MODEL    = process.env.MOONLIGHT_AI_MODEL || 'google/gemini-2.5-pro';

const aiClient = (AI_API_URL && AI_TOKEN) ? new OpenAI({ baseURL: AI_API_URL, apiKey: AI_TOKEN }) : null;

const MOONLIGHT_SYSTEM_PROMPT = `You are Moonlight AI, the assistant embedded in Moonlight Cloud, a cloud file hosting website. Help users understand and use the site accurately based on how it actually works, described below. Do not claim features that aren't listed here. You can also help with general questions — math, tech, coding, and everyday topics — like any capable assistant.

WHAT MOONLIGHT CLOUD IS
A dark-themed (purple/moon branding) cloud file storage and sharing site. Users can upload any file type, get a shareable download link, and optionally sign in with Google for expanded storage.

UPLOADING
- Anyone can upload without an account ("guest" mode). Signed-in users authenticate via "Sign in with Google."
- Any file type is accepted, no restrictions.
- There is no real malware/virus scanning. The upload flow shows a scan-style animation for UI purposes only, but it never blocks any file. Every download page honestly discloses: "We do not scan files for viruses or malware. Download at your own risk." Never claim files have been verified safe.

GUEST (NOT SIGNED IN) RULES
- Max file size: 5GB per file. No cap on total files or storage used.
- Every guest file automatically and permanently expires 7 days after upload — irreversible, even if the uploader signs in later.
- Guest files can never be marked "keep forever."

SIGNED-IN (GOOGLE ACCOUNT) RULES
- 9TB total free storage per account. No per-file size limit.
- Files default to a 30-day expiry unless "keep forever" is turned on (globally in Settings, or per file).
- If an account runs out of storage: "You're out of storage. Delete some files, or create a new account for another free 9TB." No paid tier exists.

DOWNLOADING & SHARING
- Every file gets a share link (/d/<shareId>) anyone can open to view info and download.
- The download page shows ready-to-copy terminal commands (curl/wget/PowerShell).
- A "direct link" variant (share link + /direct) skips the page entirely and starts the download instantly with zero UI.
- Video/audio files show an inline preview player; other file types never do.

MCP CONNECTOR (Claude / ChatGPT)
- Visit /mcp, click "Get MCP," sign in with Google, and get a personal, permanent MCP URL to paste into Claude or ChatGPT's connector settings — plug and play, no separate login step inside the AI client.
- Once connected, the AI can search that user's own files by name via a "search_files" tool. Read/search only — it cannot delete, modify, or upload.

MOBILE APP
- An Android app (APK, sideload-only, not on the Play Store) wraps the website in a native app shell. Same account, same files, same limits as the website.

WHAT DOES NOT EXIST (never claim these are available)
- No payment plans or paid storage tiers.
- No virtual machine / cloud compute feature.
- No general "browse any website" feature, no plugin execution system.
- No real virus/malware scanning of any kind.`;

// Cached, periodic health check — the "Moonlight AI" button is hidden
// site-wide (all accounts, including brand new ones) whenever this is false,
// rather than showing a feature that's currently broken.
let aiHealthy = false;
let lastHealthCheck = 0;
async function checkAiHealth() {
  if (!aiClient) { aiHealthy = false; return; }
  try {
    await aiClient.chat.completions.create({ model: AI_MODEL, messages: [{ role:'user', content:'ping' }], max_tokens: 5 });
    aiHealthy = true;
  } catch {
    aiHealthy = false;
  }
  lastHealthCheck = Date.now();
}
checkAiHealth();
setInterval(checkAiHealth, 5 * 60 * 1000); // re-check every 5 minutes

app.get('/api/ai/status', (req, res) => res.json({ ok:true, available: aiHealthy }));

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
  if (!aiClient) return res.status(503).json({ ok:false, error:'AI is not configured on this server yet.' });
  if (!aiHealthy) return res.status(503).json({ ok:false, error:'Moonlight AI is temporarily unavailable.' });

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
    const completion = await aiClient.chat.completions.create({
      model: AI_MODEL,
      messages: [
        { role:'system', content: MOONLIGHT_SYSTEM_PROMPT },
        ...history,
        { role:'user', content: message }
      ]
    });
    const reply = completion.choices?.[0]?.message?.content;
    if (!reply) return res.status(502).json({ ok:false, error:'Unexpected response from AI service.' });

    if (session) store.addMessage(convoId, 'assistant', reply);
    res.json({ ok:true, reply, conversationId: convoId || null });
  } catch (e) {
    aiHealthy = false; // a live failure also flips the site-wide flag immediately
    res.status(502).json({ ok:false, error:'Could not reach the AI service.', debug: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🌙 Moonlight Cloud on port ${PORT}`));
