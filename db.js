const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Store the DB under DATA_DIR if set (point this at a Railway Volume mount
// path, e.g. /data, for real persistence across restarts/redeploys). Falls
// back to the local disk otherwise — still better than pure in-memory, but
// only truly durable with a mounted Volume.
const DATA_DIR = process.env.DATA_DIR || '.';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'moonlight.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    userId TEXT PRIMARY KEY,
    keepForever INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    userId TEXT, email TEXT, name TEXT, picture TEXT,
    createdAt TEXT
  );
  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    shareId TEXT UNIQUE,
    name TEXT, size INTEGER, mimetype TEXT, hash TEXT,
    owner TEXT, ownerId TEXT,
    uploadedAt TEXT, filepath TEXT, shareUrl TEXT,
    keepForever INTEGER DEFAULT 0, expiresAt TEXT,
    isGuest INTEGER DEFAULT 0, magnetLink TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_files_owner ON files(ownerId);
`);

// ── users / keep-forever preference ─────────────────────────────────────────
function getUserKeepForever(userId) {
  const row = db.prepare('SELECT keepForever FROM users WHERE userId = ?').get(userId);
  return !!(row && row.keepForever);
}
function setUserKeepForever(userId, val) {
  db.prepare('INSERT INTO users (userId, keepForever) VALUES (?, ?) ON CONFLICT(userId) DO UPDATE SET keepForever = ?')
    .run(userId, val ? 1 : 0, val ? 1 : 0);
}

// ── sessions ──────────────────────────────────────────────────────────────────
function getSessionRow(token) {
  return db.prepare('SELECT * FROM sessions WHERE token = ?').get(token) || null;
}
function setSessionRow(token, s) {
  db.prepare(`INSERT INTO sessions (token, userId, email, name, picture, createdAt)
              VALUES (@token, @userId, @email, @name, @picture, @createdAt)`)
    .run({ token, ...s, createdAt: new Date().toISOString() });
}
function deleteSessionRow(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

// ── files ─────────────────────────────────────────────────────────────────────
function rowToFile(r) { return r ? { ...r, keepForever: !!r.keepForever, isGuest: !!r.isGuest } : null; }

function getFile(id) { return rowToFile(db.prepare('SELECT * FROM files WHERE id = ?').get(id)); }
function getFileByShare(shareId) { return rowToFile(db.prepare('SELECT * FROM files WHERE shareId = ?').get(shareId)); }
function allFiles() { return db.prepare('SELECT * FROM files').all().map(rowToFile); }
function filesByOwner(ownerId) { return db.prepare('SELECT * FROM files WHERE ownerId = ?').all(ownerId).map(rowToFile); }

function insertFile(f) {
  db.prepare(`INSERT INTO files (id, shareId, name, size, mimetype, hash, owner, ownerId,
              uploadedAt, filepath, shareUrl, keepForever, expiresAt, isGuest, magnetLink)
              VALUES (@id, @shareId, @name, @size, @mimetype, @hash, @owner, @ownerId,
              @uploadedAt, @filepath, @shareUrl, @keepForever, @expiresAt, @isGuest, @magnetLink)`)
    .run({ magnetLink: null, ...f, keepForever: f.keepForever ? 1 : 0, isGuest: f.isGuest ? 1 : 0 });
}
function updateFile(id, patch) {
  const cur = getFile(id);
  if (!cur) return;
  const next = { ...cur, ...patch };
  db.prepare(`UPDATE files SET keepForever=@keepForever, expiresAt=@expiresAt WHERE id=@id`)
    .run({ id, keepForever: next.keepForever ? 1 : 0, expiresAt: next.expiresAt });
}
function deleteFileRow(id) { db.prepare('DELETE FROM files WHERE id = ?').run(id); }

function setAllKeepForeverForOwner(ownerId) {
  db.prepare('UPDATE files SET keepForever = 1, expiresAt = NULL WHERE ownerId = ?').run(ownerId);
}

// ── Moonlight AI conversations ──────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS ai_conversations (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    title TEXT,
    createdAt TEXT, updatedAt TEXT
  );
  CREATE TABLE IF NOT EXISTS ai_messages (
    id TEXT PRIMARY KEY,
    conversationId TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    createdAt TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ai_conv_user ON ai_conversations(userId);
  CREATE INDEX IF NOT EXISTS idx_ai_msg_conv ON ai_messages(conversationId);
`);

function createConversation(userId, title) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO ai_conversations (id, userId, title, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)')
    .run(id, userId, title, now, now);
  return id;
}
function touchConversation(id) {
  db.prepare('UPDATE ai_conversations SET updatedAt = ? WHERE id = ?').run(new Date().toISOString(), id);
}
function getConversation(id) { return db.prepare('SELECT * FROM ai_conversations WHERE id = ?').get(id); }
function listConversations(userId) {
  return db.prepare('SELECT id, title, createdAt, updatedAt FROM ai_conversations WHERE userId = ? ORDER BY updatedAt DESC').all(userId);
}
function addMessage(conversationId, role, content) {
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO ai_messages (id, conversationId, role, content, createdAt) VALUES (?, ?, ?, ?, ?)')
    .run(id, conversationId, role, content, new Date().toISOString());
  touchConversation(conversationId);
}
function getMessages(conversationId) {
  return db.prepare('SELECT role, content, createdAt FROM ai_messages WHERE conversationId = ? ORDER BY createdAt ASC').all(conversationId);
}
function deleteConversation(id) {
  db.prepare('DELETE FROM ai_messages WHERE conversationId = ?').run(id);
  db.prepare('DELETE FROM ai_conversations WHERE id = ?').run(id);
}

// ── Permanent per-account MCP URL tokens ────────────────────────────────────
// A long-lived secret embedded directly in the URL path a user pastes into
// Claude/ChatGPT (https://.../mcp/u/<token>) — no separate login step inside
// the AI client. Regeneratable if it ever leaks.
db.exec(`
  CREATE TABLE IF NOT EXISTS mcp_permanent_tokens (
    userId TEXT PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    createdAt TEXT
  );
`);

function getOrCreateMcpToken(userId) {
  const row = db.prepare('SELECT token FROM mcp_permanent_tokens WHERE userId = ?').get(userId);
  if (row) return row.token;
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO mcp_permanent_tokens (userId, token, createdAt) VALUES (?, ?, ?)')
    .run(userId, token, new Date().toISOString());
  return token;
}
function regenerateMcpToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare(`INSERT INTO mcp_permanent_tokens (userId, token, createdAt) VALUES (?, ?, ?)
              ON CONFLICT(userId) DO UPDATE SET token = ?, createdAt = ?`)
    .run(userId, token, new Date().toISOString(), token, new Date().toISOString());
  return token;
}
function getUserIdByMcpToken(token) {
  const row = db.prepare('SELECT userId FROM mcp_permanent_tokens WHERE token = ?').get(token);
  return row ? row.userId : null;
}

module.exports = {
  db,
  getUserKeepForever, setUserKeepForever,
  getSessionRow, setSessionRow, deleteSessionRow,
  getFile, getFileByShare, allFiles, filesByOwner,
  insertFile, updateFile, deleteFileRow, setAllKeepForeverForOwner,
  createConversation, touchConversation, getConversation, listConversations,
  addMessage, getMessages, deleteConversation,
  getOrCreateMcpToken, regenerateMcpToken, getUserIdByMcpToken
};
