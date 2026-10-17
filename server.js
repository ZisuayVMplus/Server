'use strict';

/*
 * RainX Server Pro — JSON-only API
 * Node.js >= 20
 * Required env: BOT_SECRET, OWNER_SECRET, SESSION_SECRET
 * Optional env: PORT, DATA_DIR, TRUST_PROXY
 *
 * JSON storage is intended for one server instance.
 * Never commit secrets or rainx-data.json to GitHub.
 */

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { WebSocketServer } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: 2048
});

app.disable('x-powered-by');
app.set(
  'trust proxy',
  process.env.TRUST_PROXY === '1' ? 1 : false
);
app.use(express.json({
  limit: '128kb',
  strict: true
}));

const PORT = Number(process.env.PORT || 3000);
const BOT_SECRET = process.env.BOT_SECRET || '';
const OWNER_SECRET = process.env.OWNER_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

const DATA_DIR =
  process.env.DATA_DIR ||
  process.env.RAILWAY_VOLUME_MOUNT_PATH ||
  '/data';

const DATA_FILE = path.join(DATA_DIR, 'rainx-data.json');
const BACKUP_FILE = path.join(DATA_DIR, 'rainx-data.backup.json');

const NOW = () => Math.floor(Date.now() / 1000);
const MAX_CLOCK_SKEW = 120;
const CHALLENGE_TTL = 90;
const SESSION_TTL = 90 * 60;
const MAX_KEYS_PER_GENERATION = 50;
const MAX_JSON_BYTES = 32 * 1024 * 1024;

if (!BOT_SECRET || BOT_SECRET.length < 24) {
  console.error(
    '[SECURITY] BOT_SECRET missing or shorter than 24 chars.'
  );
}

if (!OWNER_SECRET || OWNER_SECRET.length < 24) {
  console.error(
    '[SECURITY] OWNER_SECRET missing or shorter than 24 chars.'
  );
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error(
    '[SECURITY] SESSION_SECRET must be at least 32 chars.'
  );
}

function emptyDb() {
  return {
    version: 2,
    config: {},
    guildLicenses: {},
    keys: {},
    challenges: {},
    sessions: {},
    nonceCache: {},
    audit: []
  };
}

let db = emptyDb();
let saveQueue = Promise.resolve();

const buckets = new Map();
const wsConnections = new Set();

function safeObject(value) {
  return !!value &&
    typeof value === 'object' &&
    !Array.isArray(value);
}

function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function randomKey() {
  return crypto.randomBytes(16)
    .toString('hex')
    .toUpperCase();
}

function sha256(value) {
  return crypto.createHash('sha256')
    .update(String(value))
    .digest('hex');
}

function tokenDigest(value) {
  return crypto.createHmac(
    'sha256',
    SESSION_SECRET || 'missing-session-secret'
  ).update(String(value)).digest('hex');
}

function safeEqual(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    !a ||
    !b
  ) {
    return false;
  }

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

function validId(value) {
  return typeof value === 'string' &&
    /^\d{5,25}$/.test(value);
}

function validKey(value) {
  return typeof value === 'string' &&
    /^[A-F0-9]{32}$/.test(value);
}

function validHwid(value) {
  return typeof value === 'string' &&
    /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function expired(data) {
  if (!data || data.active === false) return true;
  if (data.duration === -1) return false;

  return !data.redeemedAt ||
    data.redeemedAt <= 0 ||
    data.redeemedAt + data.duration <= NOW();
}

function publicKeyData(data) {
  return {
    ...data,
    expired: expired(data),
    active: data.active !== false
  };
}

function clientIp(req) {
  return String(
    req.ip || req.socket?.remoteAddress || 'unknown'
  ).slice(0, 100);
}

function audit(action, detail = {}) {
  db.audit.push({
    at: NOW(),
    action: String(action).slice(0, 80),
    detail
  });

  if (db.audit.length > 500) {
    db.audit.splice(0, db.audit.length - 500);
  }
}

function loadDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  for (const candidate of [DATA_FILE, BACKUP_FILE]) {
    try {
      if (!fs.existsSync(candidate)) continue;

      const stat = fs.statSync(candidate);

      if (stat.size > MAX_JSON_BYTES) {
        throw new Error('JSON file exceeds size limit');
      }

      const parsed = JSON.parse(
        fs.readFileSync(candidate, 'utf8')
      );

      if (!safeObject(parsed)) {
        throw new Error('invalid JSON root');
      }

      db = { ...emptyDb(), ...parsed };

      for (const key of [
        'config',
        'guildLicenses',
        'keys',
        'challenges',
        'sessions',
        'nonceCache'
      ]) {
        if (!safeObject(db[key])) db[key] = {};
      }

      if (!Array.isArray(db.audit)) db.audit = [];

      console.log(`[storage] Loaded ${candidate}`);
      return;
    } catch (error) {
      console.error(
        `[storage] Could not load ${candidate}: ${error.message}`
      );
    }
  }

  db = emptyDb();

  saveDb().catch(error => {
    console.error(
      '[storage] Initial save failed:',
      error.message
    );
  });
}

function saveDb() {
  saveQueue = saveQueue.catch(() => {}).then(() => {
    fs.mkdirSync(DATA_DIR, { recursive: true });

    const body = JSON.stringify(db, null, 2);

    if (Buffer.byteLength(body) > MAX_JSON_BYTES) {
      throw new Error('storage limit reached');
    }

    const tmp = `${DATA_FILE}.${process.pid}.tmp`;
    const fd = fs.openSync(tmp, 'w', 0o600);

    try {
      fs.writeFileSync(fd, body, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    if (fs.existsSync(DATA_FILE)) {
      try {
        fs.copyFileSync(DATA_FILE, BACKUP_FILE);
        fs.chmodSync(BACKUP_FILE, 0o600);
      } catch {}
    }

    fs.renameSync(tmp, DATA_FILE);

    try {
      fs.chmodSync(DATA_FILE, 0o600);
    } catch {}
  });

  return saveQueue;
}

function rateLimit({
  windowMs = 60_000,
  max = 60,
  keyFn = req => clientIp(req)
} = {}) {
  return (req, res, next) => {
    const key = `${keyFn(req)}:${req.path}`;
    const now = Date.now();

    let bucket = buckets.get(key);

    if (!bucket || now >= bucket.resetAt) {
      bucket = {
        count: 0,
        resetAt: now + windowMs
      };
    }

    bucket.count++;
    buckets.set(key, bucket);

    if (bucket.count > max) {
      res.set(
        'Retry-After',
        String(Math.max(
          1,
          Math.ceil((bucket.resetAt - now) / 1000)
        ))
      );

      return res.status(429).json({
        ok: false,
        error: 'rate_limited'
      });
    }

    next();
  };
}

function requireSecret(header, expected) {
  return (req, res, next) => {
    if (
      !expected ||
      !safeEqual(req.get(header) || '', expected)
    ) {
      return res.status(401).json({
        ok: false,
        error: 'unauthorized'
      });
    }

    next();
  };
}

const requireBot = requireSecret(
  'x-bot-secret',
  BOT_SECRET
);

const requireOwner = requireSecret(
  'x-owner-secret',
  OWNER_SECRET
);

function validClock(timestamp) {
  return Number.isInteger(timestamp) &&
    Math.abs(NOW() - timestamp) <= MAX_CLOCK_SKEW;
}

function cleanupEphemeral() {
  const now = NOW();

  for (const [id, challenge] of Object.entries(db.challenges)) {
    if (!challenge || challenge.expiresAt <= now) {
      delete db.challenges[id];
    }
  }

  for (const [id, session] of Object.entries(db.sessions)) {
    if (
      !session ||
      session.expiresAt <= now ||
      session.revoked
    ) {
      delete db.sessions[id];
    }
  }

  for (const [id, expiry] of Object.entries(db.nonceCache)) {
    if (!expiry || expiry <= now) {
      delete db.nonceCache[id];
    }
  }

  for (const [key, bucket] of buckets) {
    if (Date.now() >= bucket.resetAt + 60_000) {
      buckets.delete(key);
    }
  }
}

setInterval(() => {
  cleanupEphemeral();

  saveDb().catch(error => {
    console.error(
      '[storage] cleanup save failed:',
      error.message
    );
  });
}, 60_000).unref();

function getKey(raw) {
  return validKey(raw) ? db.keys[raw] : null;
}

function getKeyFailure(data, hwid) {
  if (!data || data.active === false) return 'key';
  if (expired(data)) return 'exp';
  if (!data.usedBy || !data.guildId) return 'key';
  if (data.hwid && data.hwid !== hwid) return 'hwid';

  return null;
}

function getLiveSession(token, hwid) {
  if (
    typeof token !== 'string' ||
    token.length < 40 ||
    token.length > 200
  ) {
    return null;
  }

  const session = db.sessions[tokenDigest(token)];

  if (
    !session ||
    session.revoked ||
    session.expiresAt <= NOW() ||
    session.hwid !== hwid
  ) {
    return null;
  }

  const key = getKey(session.key);

  if (
    !key ||
    expired(key) ||
    key.active === false ||
    key.hwid !== hwid
  ) {
    return null;
  }

  return { session, key };
}

function customHash(value) {
  let n = Number(value);

  if (!Number.isFinite(n) || n < 0) n = 0;

  for (let pass = 0; pass < 2; pass++) {
    const v1 = n % 9915 + 4;
    let v2 = 0;
    let v3 = 0;

    for (let i = 1; i <= 3; i++) {
      v2 = n % 4155 + 3;

      if (i % 2 === 1) v2 += 522;

      v3 = n % 9996 + 1;

      if (v3 % 2 !== 1) v3 *= 3;
    }

    const v4 = n % 9999995 + 1 + 13729;
    const v5 = n % 100;
    const v6 = Math.floor((n - v5) / 1000) % 1000;

    const v7 =
      v5 * v6 +
      v4 +
      (n % (419824125 - v4 + v5));

    const v8 = n % (v1 * v2 + 9999) + 13729;

    n = (
      v7 +
      ((v8 + (v5 * v2 + v6)) % 999999) *
      (v4 + (v8 % v3))
    ) % 99999999999;
  }

  return n;
}

function encryptGcmJson(obj, hexKey) {
  // Compatibility with the client using k:sub(1, 32)
  // as 32 ASCII bytes.
  const key = Buffer.from(
    hexKey.slice(0, 32),
    'utf8'
  );

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(obj), 'utf8'),
    cipher.final()
  ]);

  return {
    d: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    t: cipher.getAuthTag().toString('base64')
  };
}

// ----- Basic status -----

app.get('/', (_req, res) => {
  res.json({
    name: 'RainX API',
    status: 'running',
    version: 2
  });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/ping', (_req, res) => {
  res.json({
    ok: true,
    time: new Date().toISOString()
  });
});

// ----- Config -----

app.get('/config', requireBot, (_req, res) => {
  res.json({
    ok: true,
    config: db.config
  });
});

app.post(
  '/config',
  requireBot,
  rateLimit({ max: 120 }),
  async (req, res) => {
    if (!safeObject(req.body)) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_body'
      });
    }

    const patch = { ...req.body };

    if (Object.keys(patch).length > 100) {
      return res.status(400).json({
        ok: false,
        error: 'too_many_fields'
      });
    }

    db.config = {
      ...db.config,
      ...patch
    };

    audit('config.update', {
      fields: Object.keys(patch).slice(0, 50)
    });

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

// ----- Discord guild license -----

app.get('/guild/check/:guildId', requireBot, (req, res) => {
  const id = req.params.guildId;
  const license = validId(id)
    ? db.guildLicenses[id]
    : null;

  if (!license) {
    return res.json({
      ok: false,
      expired: true,
      note: ''
    });
  }

  const ok = license.active !== false &&
    (
      license.expiresAt === -1 ||
      license.expiresAt > NOW()
    );

  res.json({
    ok,
    expired: !ok,
    expiresAt: license.expiresAt,
    note: license.note || ''
  });
});

app.post(
  '/guild/license',
  requireOwner,
  rateLimit({ max: 30 }),
  async (req, res) => {
    const {
      guildId,
      days,
      note = ''
    } = req.body || {};

    if (!validId(guildId)) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_guild_id'
      });
    }

    if (
      !Number.isInteger(days) ||
      days < 0 ||
      days > 36500
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_days'
      });
    }

    const expiresAt = days === 0
      ? -1
      : NOW() + days * 86400;

    db.guildLicenses[guildId] = {
      expiresAt,
      note: String(note).slice(0, 300),
      active: true,
      createdAt: NOW(),
      updatedAt: NOW()
    };

    audit('guild.license.set', {
      guildId,
      days
    });

    try {
      await saveDb();
      res.json({ ok: true, expiresAt });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.post(
  '/guild/renew',
  requireOwner,
  async (req, res) => {
    const { guildId, days } = req.body || {};

    const license = validId(guildId)
      ? db.guildLicenses[guildId]
      : null;

    if (!license) {
      return res.status(404).json({
        ok: false,
        error: 'not_found'
      });
    }

    if (
      !Number.isInteger(days) ||
      days < 1 ||
      days > 36500
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_days'
      });
    }

    license.expiresAt = license.expiresAt === -1
      ? -1
      : Math.max(license.expiresAt, NOW()) +
        days * 86400;

    license.active = true;
    license.updatedAt = NOW();

    audit('guild.license.renew', {
      guildId,
      days
    });

    try {
      await saveDb();
      res.json({
        ok: true,
        expiresAt: license.expiresAt
      });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.delete(
  '/guild/license/:guildId',
  requireOwner,
  async (req, res) => {
    const id = req.params.guildId;

    if (!db.guildLicenses[id]) {
      return res.json({
        ok: false,
        error: 'not_found'
      });
    }

    delete db.guildLicenses[id];

    audit('guild.license.delete', {
      guildId: id
    });

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);
// ----- Key management API -----

app.get('/keys', requireBot, (_req, res) => {
  const keys = {};

  for (const [key, data] of Object.entries(db.keys)) {
    keys[key] = publicKeyData(data);
  }

  res.json({ ok: true, keys });
});

app.post(
  '/keys/generate',
  requireBot,
  rateLimit({ max: 30 }),
  async (req, res) => {
    const {
      duration,
      amount = 1,
      file = null
    } = req.body || {};

    if (
      !Number.isInteger(duration) ||
      (
        duration !== -1 &&
        (duration < 60 || duration > 36500 * 86400)
      )
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_duration'
      });
    }

    if (
      !Number.isInteger(amount) ||
      amount < 1 ||
      amount > MAX_KEYS_PER_GENERATION
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_amount'
      });
    }

    if (
      file !== null &&
      (typeof file !== 'string' || file.length > 80)
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_file'
      });
    }

    const keys = [];

    for (let i = 0; i < amount; i++) {
      let key;

      do {
        key = randomKey();
      } while (db.keys[key]);

      db.keys[key] = {
        active: true,
        duration,
        redeemedAt: 0,
        executionCount: 0,
        usedBy: '',
        guildId: '',
        hwid: '',
        file: file || null,
        lastHwidReset: 0,
        createdAt: NOW(),
        updatedAt: NOW(),
        revokedAt: 0
      };

      keys.push(key);
    }

    audit('keys.generate', {
      amount,
      duration,
      file: file || null
    });

    try {
      await saveDb();
      res.json({ ok: true, keys });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.get('/keys/user/:userId', requireBot, (req, res) => {
  const userId = req.params.userId;
  const guildId = String(req.query.guildId || '');

  if (!validId(userId) || !validId(guildId)) {
    return res.status(400).json({
      ok: false,
      error: 'invalid_id'
    });
  }

  const pair = Object.entries(db.keys).find(
    ([, data]) =>
      data.usedBy === userId &&
      data.guildId === guildId &&
      data.active !== false
  );

  if (!pair) {
    return res.json({
      ok: false,
      error: 'not_found'
    });
  }

  res.json({
    ok: true,
    key: pair[0],
    data: publicKeyData(pair[1])
  });
});

app.get('/keys/:keyName', requireBot, (req, res) => {
  const keyName = req.params.keyName;
  const data = getKey(keyName);

  if (!data) {
    return res.status(404).json({
      ok: false,
      error: 'not_found'
    });
  }

  res.json({
    ok: true,
    key: keyName,
    data: publicKeyData(data)
  });
});

app.post(
  '/keys/:keyName/redeem',
  requireBot,
  rateLimit({ max: 60 }),
  async (req, res) => {
    const keyName = req.params.keyName;
    const data = getKey(keyName);
    const { userId, guildId } = req.body || {};

    if (!data || data.active === false) {
      return res.json({
        ok: false,
        reason: 'Key ไม่ถูกต้อง'
      });
    }

    if (!validId(userId) || !validId(guildId)) {
      return res.status(400).json({
        ok: false,
        reason: 'Key ไม่ถูกต้อง'
      });
    }

    if (expired(data)) {
      return res.json({
        ok: false,
        reason: 'Key หมดอายุแล้ว'
      });
    }

    if (data.usedBy && data.usedBy !== userId) {
      return res.json({
        ok: false,
        reason: 'Key used by someone else'
      });
    }

    if (data.guildId && data.guildId !== guildId) {
      return res.json({
        ok: false,
        reason: 'Key used in another guild'
      });
    }

    if (
      data.usedBy === userId &&
      data.guildId === guildId
    ) {
      return res.json({
        ok: false,
        reason: 'Already redeemed'
      });
    }

    data.usedBy = userId;
    data.guildId = guildId;
    data.redeemedAt = NOW();
    data.updatedAt = NOW();

    audit('key.redeem', {
      keySuffix: keyName.slice(-6),
      userId,
      guildId
    });

    try {
      await saveDb();
      res.json({
        ok: true,
        duration: data.duration
      });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.delete(
  '/keys/:keyName',
  requireBot,
  async (req, res) => {
    const keyName = req.params.keyName;

    if (!getKey(keyName)) {
      return res.json({
        ok: false,
        error: 'not_found'
      });
    }

    for (const [id, session] of Object.entries(db.sessions)) {
      if (session.key === keyName) {
        delete db.sessions[id];
      }
    }

    delete db.keys[keyName];

    audit('key.delete', {
      keySuffix: String(keyName).slice(-6)
    });

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.post(
  '/keys/:keyName/reset-hwid',
  requireBot,
  async (req, res) => {
    const keyName = req.params.keyName;
    const data = getKey(keyName);

    if (!data) {
      return res.status(404).json({
        ok: false,
        error: 'not_found'
      });
    }

    data.hwid = '';
    data.lastHwidReset = NOW();
    data.updatedAt = NOW();

    for (const [id, session] of Object.entries(db.sessions)) {
      if (session.key === keyName) {
        delete db.sessions[id];
      }
    }

    audit('key.hwid.reset', {
      keySuffix: keyName.slice(-6)
    });

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

app.post(
  '/keys/:keyName/revoke',
  requireBot,
  async (req, res) => {
    const keyName = req.params.keyName;
    const data = getKey(keyName);

    if (!data) {
      return res.status(404).json({
        ok: false,
        error: 'not_found'
      });
    }

    data.active = false;
    data.revokedAt = NOW();
    data.updatedAt = NOW();

    for (const [id, session] of Object.entries(db.sessions)) {
      if (session.key === keyName) {
        delete db.sessions[id];
      }
    }

    audit('key.revoke', {
      keySuffix: keyName.slice(-6)
    });

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

// ----- Client authorization protocol -----

app.post(
  '/cdn-cgi/challenge',
  rateLimit({ windowMs: 60_000, max: 15 }),
  async (req, res) => {
    const { key, hwid, ts, nonce } = req.body || {};

    if (SESSION_SECRET.length < 32) {
      return res.status(503).json({ e: 'rate' });
    }

    if (!validKey(key)) {
      return res.status(200).json({ e: 'key' });
    }

    if (!validHwid(hwid)) {
      return res.status(200).json({ e: 'key' });
    }

    if (!validClock(ts)) {
      return res.status(200).json({ e: 'rate' });
    }

    if (
      typeof nonce !== 'string' ||
      !/^[a-fA-F0-9]{16,64}$/.test(nonce)
    ) {
      return res.status(200).json({ e: 'rate' });
    }

    const nonceId = sha256(`${clientIp(req)}:${nonce}`);

    if (
      db.nonceCache[nonceId] &&
      db.nonceCache[nonceId] > NOW()
    ) {
      return res.status(200).json({ e: 'rate' });
    }

    db.nonceCache[nonceId] = NOW() + 180;

    const data = getKey(key);
    const failure = getKeyFailure(data, hwid);

    if (failure) {
      await saveDb().catch(() => {});
      return res.status(200).json({ e: failure });
    }

    if (!data.hwid) {
      data.hwid = hwid;
      data.updatedAt = NOW();
    }

    data.executionCount = (data.executionCount || 0) + 1;
    data.updatedAt = NOW();

    const challengeId = randomHex(24);
    const challengeKey = randomHex(32);

    db.challenges[challengeId] = {
      key,
      hwid,
      nonce,
      k: challengeKey,
      createdAt: NOW(),
      expiresAt: NOW() + CHALLENGE_TTL,
      ipHash: sha256(clientIp(req))
    };

    audit('client.challenge', {
      keySuffix: key.slice(-6)
    });

    try {
      await saveDb();

      res.json({
        s: challengeId,
        k: challengeKey
      });
    } catch {
      res.status(500).json({ e: 'rate' });
    }
  }
);

app.post(
  '/cdn-cgi/token',
  rateLimit({ windowMs: 60_000, max: 20 }),
  async (req, res) => {
    const { s, hwid, ts, nonce } = req.body || {};

    if (
      typeof s !== 'string' ||
      s.length > 128 ||
      !validHwid(hwid) ||
      !validClock(ts) ||
      typeof nonce !== 'string'
    ) {
      return res.json({ e: 'rate' });
    }

    const challenge = db.challenges[s];

    if (
      !challenge ||
      challenge.expiresAt <= NOW() ||
      challenge.hwid !== hwid ||
      challenge.nonce !== nonce
    ) {
      return res.json({ e: 'key' });
    }

    const data = getKey(challenge.key);
    const failure = getKeyFailure(data, hwid);

    if (failure) {
      delete db.challenges[s];
      await saveDb().catch(() => {});
      return res.json({ e: failure });
    }

    // Consume the challenge so it cannot be reused.
    delete db.challenges[s];

    const activeToken = randomHex(32);
    const tokenHash = tokenDigest(activeToken);

    db.sessions[tokenHash] = {
      key: challenge.key,
      hwid,
      createdAt: NOW(),
      expiresAt: NOW() + SESSION_TTL,
      revoked: false,
      ipHash: sha256(clientIp(req)),
      lastSeenAt: NOW()
    };

    const payload = encryptGcmJson(
      { ok: true, activeToken },
      challenge.k
    );

    audit('client.session.create', {
      keySuffix: challenge.key.slice(-6)
    });

    try {
      await saveDb();
      res.json(payload);
    } catch {
      res.status(500).json({ e: 'rate' });
    }
  }
);

app.post(
  '/cdn-cgi/validate',
  rateLimit({ windowMs: 60_000, max: 60 }),
  async (req, res) => {
    const {
      token,
      hwid,
      h1,
      h2,
      ts
    } = req.body || {};

    if (!validClock(ts) || !validHwid(hwid)) {
      return res.json({ ok: false });
    }

    const live = getLiveSession(token, hwid);

    if (!live) {
      return res.json({ ok: false });
    }

    // This is a compatibility check, not proof of client integrity.
    const seed = crypto.randomInt(1000, 999999);
    const check = String(
      customHash(Number(h1) + seed)
    );

    live.session.lastSeenAt = NOW();
    live.session.expiresAt = NOW() + SESSION_TTL;

    await saveDb().catch(() => {});

    res.json({
      ok: true,
      seed,
      check
    });
  }
);

app.post(
  '/cdn-cgi/heartbeat',
  rateLimit({ windowMs: 60_000, max: 20 }),
  async (req, res) => {
    const {
      token,
      hwid,
      ts,
      ping
    } = req.body || {};

    if (
      !validClock(ts) ||
      !validHwid(hwid) ||
      !Number.isFinite(Number(ping))
    ) {
      return res.json({ alive: false });
    }

    const live = getLiveSession(token, hwid);

    if (!live) {
      return res.json({ alive: false });
    }

    live.session.lastSeenAt = NOW();
    live.session.expiresAt = NOW() + SESSION_TTL;

    await saveDb().catch(() => {});

    res.json({ alive: true });
  }
);

// ----- Owner-only emergency session revocation -----

app.post(
  '/admin/revoke-session',
  requireOwner,
  async (req, res) => {
    const token = req.body?.token;

    if (
      typeof token !== 'string' ||
      token.length > 200
    ) {
      return res.status(400).json({
        ok: false,
        error: 'invalid_token'
      });
    }

    const id = tokenDigest(token);

    if (db.sessions[id]) {
      delete db.sessions[id];
    }

    audit('session.revoke', {});

    try {
      await saveDb();
      res.json({ ok: true });
    } catch {
      res.status(500).json({
        ok: false,
        error: 'storage_error'
      });
    }
  }
);

// ----- WebSocket heartbeat -----

server.on('upgrade', (request, socket, head) => {
  let pathname;

  try {
    pathname = new URL(
      request.url,
      'http://localhost'
    ).pathname;
  } catch {
    socket.destroy();
    return;
  }

  if (pathname !== '/cdn-cgi/ws') {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(
    request,
    socket,
    head,
    ws => wss.emit('connection', ws, request)
  );
});

wss.on('connection', ws => {
  wsConnections.add(ws);

  ws.on('message', async raw => {
    try {
      const message = JSON.parse(raw.toString());

      if (
        message.op !== 'PING' ||
        !validHwid(message.hwid) ||
        !validClock(message.ts)
      ) {
        ws.close(1008, 'invalid');
        return;
      }

      const live = getLiveSession(
        message.token,
        message.hwid
      );

      if (!live) {
        ws.close(1008, 'expired');
        return;
      }

      live.session.lastSeenAt = NOW();
      live.session.expiresAt = NOW() + SESSION_TTL;

      ws.send('PONG');

      saveDb().catch(() => {});
    } catch {
      ws.close(1008, 'invalid');
    }
  });

  ws.on('close', () => wsConnections.delete(ws));
  ws.on('error', () => wsConnections.delete(ws));
});

// ----- Error handling -----

app.use((_req, res) => {
  res.status(404).json({
    ok: false,
    error: 'not_found'
  });
});

app.use((err, _req, res, _next) => {
  if (
    err instanceof SyntaxError &&
    'body' in err
  ) {
    return res.status(400).json({
      ok: false,
      error: 'invalid_json'
    });
  }

  if (err?.type === 'entity.too.large') {
    return res.status(413).json({
      ok: false,
      error: 'body_too_large'
    });
  }

  console.error(
    '[server error]',
    err?.message || 'unknown'
  );

  res.status(500).json({
    ok: false,
    error: 'internal_error'
  });
});

// ----- Startup and graceful shutdown -----

loadDb();

server.listen(PORT, '0.0.0.0', () => {
  console.log(
    `[RainX API Pro] listening on ${PORT}; data=${DATA_FILE}`
  );
});

process.on('SIGTERM', async () => {
  try {
    await saveDb();
  } catch (error) {
    console.error(
      '[shutdown] save failed:',
      error.message
    );
  }

  server.close(() => process.exit(0));

  setTimeout(() => process.exit(1), 8000).unref();
});
