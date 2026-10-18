
'use strict';

const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

const PORT = Number(process.env.PORT || 3000);
const BOT_SECRET = process.env.BOT_SECRET || '';
const OWNER_SECRET = process.env.OWNER_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

const DATA_DIR = process.env.DATA_DIR || './data';
const DATA_FILE = path.join(DATA_DIR, 'rainx.json');

const NOW = () => Math.floor(Date.now() / 1000);
const CHALLENGE_TTL = 90;
const SESSION_TTL = 90 * 60;

function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function digestToken(token) {
  return crypto.createHmac('sha256', SESSION_SECRET)
    .update(String(token)).digest('hex');
}

function equalSecret(a, b) {
  if (!a || !b) return false;
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function emptyDB() {
  return {
    version: 1,
    config: { projectName: 'RainX', maintenance: false },
    keys: {},
    challenges: {},
    sessions: {},
    nonces: {}
  };
}

let db = emptyDB();
let saveQueue = Promise.resolve();

function loadDB() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  try {
    if (fs.existsSync(DATA_FILE)) {
      const loaded = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!loaded || typeof loaded !== 'object' || Array.isArray(loaded)) {
        throw new Error('Invalid database');
      }
      db = { ...emptyDB(), ...loaded };
      for (const key of ['config', 'keys', 'challenges', 'sessions', 'nonces']) {
        if (!db[key] || typeof db[key] !== 'object' || Array.isArray(db[key])) {
          db[key] = {};
        }
      }
    }
  } catch (error) {
    console.error('Database load error:', error.message);
    throw error;
  }
}

function saveDB() {
  saveQueue = saveQueue.catch(() => {}).then(() => {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const temp = DATA_FILE + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(db, null, 2), { mode: 0o600 });
    fs.renameSync(temp, DATA_FILE);
  });
  return saveQueue;
}

function validKey(key) {
  return typeof key === 'string' && /^[A-F0-9]{32}$/.test(key);
}

function validHwid(hwid) {
  return typeof hwid === 'string' &&
    /^[A-Za-z0-9_-]{1,128}$/.test(hwid);
}

function validClock(ts) {
  return Number.isInteger(ts) && Math.abs(NOW() - ts) <= 120;
}

function keyExpired(key) {
  if (!key || key.active === false) return true;
  if (!key.redeemedAt) return false;
  if (key.duration === -1) return false;
  return NOW() >= key.redeemedAt + key.duration;
}

function keyFailure(key, hwid) {
  if (!key || key.active === false) return 'key';
  if (keyExpired(key)) return 'exp';
  if (!key.redeemedAt) return 'key';
  if (key.hwid && key.hwid !== hwid) return 'hwid';
  return null;
}

function cleanup() {
  const now = NOW();

  for (const [id, item] of Object.entries(db.challenges)) {
    if (!item || item.expiresAt <= now) delete db.challenges[id];
  }

  for (const [id, item] of Object.entries(db.sessions)) {
    if (!item || item.expiresAt <= now || item.revoked) {
      delete db.sessions[id];
    }
  }

  for (const [id, expiry] of Object.entries(db.nonces)) {
    if (expiry <= now) delete db.nonces[id];
  }
}

function requireSecret(name, secret) {
  return (req, res, next) => {
    if (!secret || !equalSecret(req.get(name), secret)) {
      return res.status(401).json({
        ok: false,
        error: 'unauthorized'
      });
    }
    next();
  };
}

const requireBot = requireSecret('x-bot-secret', BOT_SECRET);
const requireOwner = requireSecret('x-owner-secret', OWNER_SECRET);

function liveSession(token, hwid) {
  if (typeof token !== 'string' || token.length > 200) return null;

  const session = db.sessions[digestToken(token)];
  if (!session || session.revoked || session.expiresAt <= NOW()) return null;
  if (session.hwid !== hwid) return null;

  const key = db.keys[session.key];
  if (keyFailure(key, hwid)) return null;

  return { session, key };
}

function customHash(value) {
  let n = Number(value);
  if (!Number.isFinite(n) || n < 0) n = 0;

  for (let pass = 0; pass < 2; pass++) {
    const v1 = n % 9915 + 4;
    let v2 = 0, v3 = 0;

    for (let i = 1; i <= 3; i++) {
      v2 = n % 4155 + 3;
      if (i % 2 === 1) v2 += 522;
      v3 = n % 9996 + 1;
      if (v3 % 2 !== 1) v3 *= 3;
    }

    const v4 = n % 9999995 + 1 + 13729;
    const v5 = n % 100;
    const v6 = Math.floor((n - v5) / 1000) % 1000;
    const v7 = v5 * v6 + v4 + (n % (419824125 - v4 + v5));
    const v8 = n % (v1 * v2 + 9999) + 13729;

    n = (v7 + ((v8 + (v5 * v2 + v6)) % 999999) *
      (v4 + (v8 % v3))) % 99999999999;
  }

  return n;
}

function encryptToken(payload, challengeKey) {
  // Compatible with the paired client that uses the first 32
  // ASCII characters of challengeKey as the AES-256-GCM key.
  const aesKey = Buffer.from(challengeKey.slice(0, 32), 'utf8');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final()
  ]);

  return {
    d: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    t: cipher.getAuthTag().toString('base64')
  };
}

// --------------------------------------------------
// Public status pages
// --------------------------------------------------

app.get('/', (_req, res) => {
  res.json({
    name: 'RainX API',
    status: 'running',
    version: 3
  });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/ping', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get('/api/status', (_req, res) => {
  res.json({
    ok: true,
    service: 'RainX',
    version: 3,
    maintenance: Boolean(db.config.maintenance),
    endpoints: [
      '/health',
      '/api/status',
      '/cdn-cgi/challenge',
      '/cdn-cgi/token',
      '/cdn-cgi/validate',
      '/cdn-cgi/heartbeat'
    ]
  });
});

app.get('/config', requireBot, (_req, res) => {
  res.json({ ok: true, config: db.config });
});

app.post('/config', requireOwner, async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ ok: false, error: 'invalid_body' });
  }

  db.config = { ...db.config, ...req.body };
  try {
    await saveDB();
    res.json({ ok: true, config: db.config });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

// --------------------------------------------------
// Key management (protected bot API)
// duration: seconds; -1 = permanent
// --------------------------------------------------

app.get('/keys', requireBot, (_req, res) => {
  res.json({ ok: true, keys: db.keys });
});

app.post('/keys/generate', requireBot, async (req, res) => {
  const duration = req.body?.duration;
  const amount = req.body?.amount ?? 1;

  if (!Number.isInteger(duration) ||
      (duration !== -1 && (duration < 60 || duration > 3153600000))) {
    return res.status(400).json({ ok: false, error: 'invalid_duration' });
  }

  if (!Number.isInteger(amount) || amount < 1 || amount > 50) {
    return res.status(400).json({ ok: false, error: 'invalid_amount' });
  }

  const keys = [];

  for (let i = 0; i < amount; i++) {
    let key;
    do {
      key = randomHex(16).toUpperCase();
    } while (db.keys[key]);

    db.keys[key] = {
      active: true,
      duration,
      redeemedAt: 0,
      usedBy: '',
      guildId: '',
      hwid: '',
      createdAt: NOW()
    };

    keys.push(key);
  }

  try {
    await saveDB();
    res.json({ ok: true, keys });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

app.post('/keys/:key/redeem', requireBot, async (req, res) => {
  const keyName = req.params.key;
  const key = db.keys[keyName];
  const { userId, guildId } = req.body || {};

  if (!validKey(keyName) || !key || key.active === false) {
    return res.json({ ok: false, error: 'invalid_key' });
  }

  if (!/^\d{5,25}$/.test(String(userId || '')) ||
      !/^\d{5,25}$/.test(String(guildId || ''))) {
    return res.status(400).json({ ok: false, error: 'invalid_id' });
  }

  if (keyExpired(key)) {
    return res.json({ ok: false, error: 'expired_key' });
  }

  if (key.usedBy || key.guildId) {
    return res.json({ ok: false, error: 'already_redeemed' });
  }

  key.usedBy = String(userId);
  key.guildId = String(guildId);
  key.redeemedAt = NOW();

  try {
    await saveDB();
    res.json({ ok: true, duration: key.duration });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

app.post('/keys/:key/reset-hwid', requireBot, async (req, res) => {
  const key = db.keys[req.params.key];

  if (!key) return res.status(404).json({ ok: false, error: 'not_found' });

  key.hwid = '';

  for (const [id, session] of Object.entries(db.sessions)) {
    if (session.key === req.params.key) delete db.sessions[id];
  }

  try {
    await saveDB();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

app.post('/keys/:key/revoke', requireBot, async (req, res) => {
  const keyName = req.params.key;
  const key = db.keys[keyName];

  if (!key) return res.status(404).json({ ok: false, error: 'not_found' });

  key.active = false;

  for (const [id, session] of Object.entries(db.sessions)) {
    if (session.key === keyName) delete db.sessions[id];
  }

  try {
    await saveDB();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

// --------------------------------------------------
// Client authorization: Challenge -> Token -> Validate
// --------------------------------------------------

app.post('/cdn-cgi/challenge', async (req, res) => {
  if (db.config.maintenance) {
    return res.json({ e: 'maintenance' });
  }

  const { key, hwid, ts, nonce } = req.body || {};

  if (SESSION_SECRET.length < 32) {
    return res.status(503).json({ e: 'server_config' });
  }

  if (!validKey(key)) return res.json({ e: 'key' });
  if (!validHwid(hwid)) return res.json({ e: 'hwid' });
  if (!validClock(ts)) return res.json({ e: 'rate' });

  if (typeof nonce !== 'string' || !/^[a-fA-F0-9]{16,64}$/.test(nonce)) {
    return res.json({ e: 'rate' });
  }

  cleanup();

  const nonceId = sha256(nonce);
  if (db.nonces[nonceId]) return res.json({ e: 'rate' });

  db.nonces[nonceId] = NOW() + 180;

  const license = db.keys[key];
  const failure = keyFailure(license, hwid);

  if (failure) {
    await saveDB().catch(() => {});
    return res.json({ e: failure });
  }

  if (!license.hwid) license.hwid = hwid;

  const s = randomHex(24);
  const k = randomHex(32);

  db.challenges[s] = {
    key,
    hwid,
    nonce,
    k,
    expiresAt: NOW() + CHALLENGE_TTL
  };

  try {
    await saveDB();
    res.json({ s, k });
  } catch {
    res.status(500).json({ e: 'storage_error' });
  }
});

app.post('/cdn-cgi/token', async (req, res) => {
  const { s, hwid, ts, nonce } = req.body || {};

  if (!validHwid(hwid) || !validClock(ts) ||
      typeof s !== 'string' || typeof nonce !== 'string') {
    return res.json({ e: 'rate' });
  }

  const challenge = db.challenges[s];

  if (!challenge || challenge.expiresAt <= NOW() ||
      challenge.hwid !== hwid || challenge.nonce !== nonce) {
    return res.json({ e: 'key' });
  }

  delete db.challenges[s];

  const license = db.keys[challenge.key];
  const failure = keyFailure(license, hwid);

  if (failure) {
    await saveDB().catch(() => {});
    return res.json({ e: failure });
  }

  const activeToken = randomHex(32);

  db.sessions[digestToken(activeToken)] = {
    key: challenge.key,
    hwid,
    createdAt: NOW(),
    expiresAt: NOW() + SESSION_TTL,
    revoked: false
  };

  try {
    await saveDB();
    res.json(encryptToken({ ok: true, activeToken }, challenge.k));
  } catch {
    res.status(500).json({ e: 'storage_error' });
  }
});

app.post('/cdn-cgi/validate', async (req, res) => {
  const { token, hwid, h1, ts } = req.body || {};

  if (!validHwid(hwid) || !validClock(ts)) {
    return res.json({ ok: false, error: 'invalid_request' });
  }

  const live = liveSession(token, hwid);

  if (!live) return res.json({ ok: false, error: 'invalid_session' });

  const seed = crypto.randomInt(1000, 999999);
  const check = String(customHash(Number(h1) + seed));

  live.session.expiresAt = NOW() + SESSION_TTL;

  await saveDB().catch(() => {});

  res.json({
    ok: true,
    seed,
    check,
    expiresAt: live.session.expiresAt
  });
});

app.post('/cdn-cgi/heartbeat', async (req, res) => {
  const { token, hwid, ts, ping } = req.body || {};

  if (!validHwid(hwid) || !validClock(ts) ||
      !Number.isFinite(Number(ping))) {
    return res.json({ alive: false, error: 'invalid_request' });
  }

  const live = liveSession(token, hwid);

  if (!live) return res.json({ alive: false, error: 'invalid_session' });

  live.session.expiresAt = NOW() + SESSION_TTL;

  await saveDB().catch(() => {});

  res.json({
    alive: true,
    expiresAt: live.session.expiresAt
  });
});

// --------------------------------------------------
// Owner: revoke an active session
// --------------------------------------------------

app.post('/admin/revoke-session', requireOwner, async (req, res) => {
  const token = req.body?.token;

  if (typeof token !== 'string' || !token) {
    return res.status(400).json({ ok: false, error: 'invalid_token' });
  }

  delete db.sessions[digestToken(token)];

  try {
    await saveDB();
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: 'storage_error' });
  }
});

// --------------------------------------------------
// Errors
// --------------------------------------------------

app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'not_found' });
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError) {
    return res.status(400).json({ ok: false, error: 'invalid_json' });
  }

  console.error('[RainX]', err.message);
  res.status(500).json({ ok: false, error: 'internal_error' });
});

if (BOT_SECRET.length < 24 ||
    OWNER_SECRET.length < 24 ||
    SESSION_SECRET.length < 32) {
  console.error(
    'Set BOT_SECRET (24+ chars), OWNER_SECRET (24+ chars), ' +
    'and SESSION_SECRET (32+ chars) in environment variables.'
  );
}

loadDB();

setInterval(() => {
  cleanup();
  saveDB().catch(err => console.error('Cleanup save error:', err.message));
}, 60_000).unref();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[RainX API] Listening on port ${PORT}`);
});
