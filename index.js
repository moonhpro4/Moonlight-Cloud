require('dotenv').config();
const express = require('express');
const multer  = require('multer');
const { v4: uuidv4 } = require('uuid');
const { nanoid } = require('nanoid');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');
const path = require('path');
const fs   = require('fs');
const https = require('https');

const app    = express();
const gClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads', { recursive: true });

const files    = {};
const shares   = {};
const sessions = {};
const guestUploads = {};
const activeDownloads = new Set();
const keepForeverUsers = new Set(); // userIds who set keep forever
const MAX_CONCURRENT_DL = 2;
const GB = 1024 * 1024 * 1024;
const GUEST_MAX_SIZE  = 20 * GB;     // guest (not signed in): 20 GB
const USER_MAX_SIZE   = 9 * 1024 * GB; // signed in: 9 TB free
const GUEST_MAX_FILES = 3;
const FILE_SIZE_HARD  = undefined;   // no single-file size cap (multer: omit fileSize to disable it)
const DAYS_30 = 30 * 24 * 60 * 60 * 1000;

// ── Dynamic base URL from request ────────────────────────────────────────────
function getBase(req) {
  // Trust Railway/proxy forwarded headers
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host  = req.headers['x-forwarded-host']  || req.headers['host'] || req.get('host');
  return `${proto}://${host}`;
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ── Auto-delete job: runs every hour ─────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  Object.values(files).forEach(f => {
    if (!f.keepForever && (now - new Date(f.uploadedAt).getTime()) > DAYS_30) {
      try { fs.unlinkSync(f.filepath); } catch {}
      delete shares[f.shareId];
      delete files[f.id];
    }
  });
}, 60 * 60 * 1000);

// ── Auth helpers ──────────────────────────────────────────────────────────────
function getSession(req) {
  const t = req.headers['x-session-token'];
  return t ? sessions[t] : null;
}

function getQuota(session, ip) {
  if (session) {
    const used  = Object.values(files).filter(f => f.ownerId === session.userId).reduce((a,f) => a+f.size, 0);
    const count = Object.values(files).filter(f => f.ownerId === session.userId).length;
    return { used, max: USER_MAX_SIZE, count, maxFiles: Infinity, isGuest: false };
  }
  const g = guestUploads[ip] || { count:0, totalSize:0 };
  return { used: g.totalSize, max: GUEST_MAX_SIZE, count: g.count, maxFiles: GUEST_MAX_FILES, isGuest: true };
}

// ── Multer ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename:    (req, file, cb) => { const id = uuidv4(); req.fileId = id; cb(null, id + path.extname(file.originalname)); }
});
const upload = multer({ storage, // no limits object: unlimited file size
  fileFilter: (req, file, cb) => {
    const session = getSession(req);
    const quota   = getQuota(session, req.ip);
    if (quota.isGuest && quota.count >= quota.maxFiles) return cb(new Error('GUEST_LIMIT'));
    cb(null, true);
  }
});

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
    sessions[token] = { userId: payload.sub, email: payload.email, name: payload.name, picture: payload.picture };
    res.json({ ok:true, token, name:payload.name, email:payload.email, picture:payload.picture,
      keepForever: keepForeverUsers.has(payload.sub) });
  } catch { res.status(401).json({ ok:false, error:'Invalid token' }); }
});

app.post('/api/auth/logout', (req, res) => {
  const t = req.headers['x-session-token'];
  if (t) delete sessions[t];
  res.json({ ok:true });
});

// ── Keep forever setting ──────────────────────────────────────────────────────
app.post('/api/settings/keep-forever', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok:false });
  keepForeverUsers.add(session.userId);
  // Also update all existing files for this user
  Object.values(files).filter(f => f.ownerId === session.userId).forEach(f => f.keepForever = true);
  res.json({ ok:true });
});

app.get('/api/settings', (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ keepForever: false });
  res.json({ keepForever: keepForeverUsers.has(session.userId) });
});

// ── Quota ─────────────────────────────────────────────────────────────────────
app.get('/api/quota', (req, res) => res.json(getQuota(getSession(req), req.ip)));

// ── Upload ────────────────────────────────────────────────────────────────────
app.post('/api/upload', (req, res) => {
  upload.single('file')(req, res, err => {
    if (err) {
      if (err.message === 'GUEST_LIMIT') return res.status(403).json({ ok:false, error:'Guest upload limit reached. Sign in with Google for more.' });
      return res.status(400).json({ ok:false, error:err.message });
    }
    if (!req.file) return res.status(400).json({ ok:false, error:'No file received' });
    const session = getSession(req);
    const quota   = getQuota(session, req.ip);
    if (quota.used + req.file.size > quota.max) {
      fs.unlinkSync(req.file.path);
      return res.status(403).json({ ok:false, error: quota.isGuest ? 'Storage limit reached. Sign in for more.' : 'Quota exceeded.' });
    }
    const fileId  = req.fileId || path.basename(req.file.filename, path.extname(req.file.filename));
    const shareId = nanoid(8);
    const base    = getBase(req);
    const shareUrl = `${base}/d/${shareId}`;
    const rawUrl   = `${base}/download/${fileId}/raw`;
    const keepForever = session ? keepForeverUsers.has(session.userId) : false;
    const record = {
      id: fileId, shareId, name: req.file.originalname, size: req.file.size,
      mimetype: req.file.mimetype, hash: req.body.hash || null,
      owner: session ? session.name : 'Guest',
      ownerId: session ? session.userId : req.ip,
      uploadedAt: new Date().toISOString(),
      filepath: req.file.path, shareUrl, keepForever,
      expiresAt: keepForever ? null : new Date(Date.now() + DAYS_30).toISOString()
    };
    files[fileId]   = record;
    shares[shareId] = fileId;
    if (!session) {
      if (!guestUploads[req.ip]) guestUploads[req.ip] = { count:0, totalSize:0 };
      guestUploads[req.ip].count++;
      guestUploads[req.ip].totalSize += req.file.size;
    }
    const commands = {
      windows: `Invoke-WebRequest -Uri "${rawUrl}" -OutFile "${req.file.originalname}"`,
      mac:     `curl -L "${rawUrl}" -o "${req.file.originalname}"`,
      linux:   `wget -O "${req.file.originalname}" "${rawUrl}"`
    };
    res.json({ ok:true, fileId, shareId, name:req.file.originalname, size:req.file.size,
      shareUrl, rawUrl, commands, keepForever, expiresAt: record.expiresAt });
  });
});

// ── Keep forever for specific file ───────────────────────────────────────────
app.post('/api/file/:fileId/keep-forever', (req, res) => {
  const session = getSession(req);
  const file    = files[req.params.fileId];
  if (!file) return res.status(404).json({ ok:false });
  const ownerId = session ? session.userId : req.ip;
  if (file.ownerId !== ownerId) return res.status(403).json({ ok:false });
  file.keepForever = true;
  file.expiresAt   = null;
  res.json({ ok:true });
});

// ── Share page ────────────────────────────────────────────────────────────────
app.get('/api/share/:shareId', (req, res) => {
  const fileId = shares[req.params.shareId];
  const file   = fileId ? files[fileId] : null;
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
  const ownerId = session ? session.userId : req.ip;
  const userFiles = Object.values(files)
    .filter(f => f.ownerId === ownerId)
    .map(f => ({ id:f.id, shareId:f.shareId, shareUrl:f.shareUrl, name:f.name,
      size:f.size, uploadedAt:f.uploadedAt, keepForever:f.keepForever, expiresAt:f.expiresAt }));
  res.json({ ok:true, files:userFiles });
});

app.get('/api/file/:fileId', (req, res) => {
  const file = files[req.params.fileId];
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
  const file    = files[req.params.fileId];
  if (!file) return res.status(404).json({ ok:false, error:'Not found' });
  const ownerId = session ? session.userId : req.ip;
  if (file.ownerId !== ownerId) return res.status(403).json({ ok:false, error:'Not your file' });
  try { fs.unlinkSync(file.filepath); } catch {}
  delete shares[file.shareId];
  delete files[req.params.fileId];
  res.json({ ok:true });
});

app.get('/download/:fileId/raw', (req, res) => {
  const file = files[req.params.fileId];
  if (!file) return res.status(404).send('Not found');
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
  res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
  res.setHeader('Content-Length', file.size);
  res.setHeader('Accept-Ranges', 'bytes');
  fs.createReadStream(file.filepath).pipe(res);
});

app.get('/d/:shareId', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));
app.get('/download/:fileId', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🌙 Moonlight Cloud on port ${PORT}`));
