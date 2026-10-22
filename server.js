// ====================================================
// RainX Server v3 — by นาย
// ====================================================
const express    = require("express");
const crypto     = require("crypto");
const fs         = require("fs");
const path       = require("path");
const { WebSocketServer } = require("ws");
const http       = require("http");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: "/cdn-cgi/ws" });

app.use(express.json());

// ====================================================
// CONFIG
// ====================================================
const BOT_SECRET     = process.env.BOT_SECRET     || "BOT_SECRE";
const OWNER_SECRET   = process.env.OWNER_SECRET   || "OWNER_SECRET";
const SESSION_SECRET = process.env.SESSION_SECRET || "SESSION_SECRET";
const PORT           = process.env.PORT            || 3000;
const DB_PATH        = path.join(__dirname, "db.json");

// ====================================================
// IN-MEMORY DB (+ JSON persistence)
// ====================================================
let db = {
    keys:       {},   // keyName → keyData
    sessions:   {},   // activeToken → sessionData
    challenges: {},   // nonce → challengeData
    config:     { allowedGames: [], maxSessions: 1, version: 3 },
};

function saveDb() {
    try {
        const { challenges, ...safe } = db; // ไม่ save challenges (temporary)
        fs.writeFileSync(DB_PATH, JSON.stringify(safe, null, 2));
    } catch (e) { console.error("[DB] save error", e.message); }
}

function loadDb() {
    try {
        if (fs.existsSync(DB_PATH)) {
            const raw = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
            db.keys     = raw.keys     || {};
            db.sessions = raw.sessions || {};
            db.config   = { ...db.config, ...(raw.config || {}) };
            console.log(`[DB] loaded — keys: ${Object.keys(db.keys).length}, sessions: ${Object.keys(db.sessions).length}`);
        }
    } catch (e) { console.error("[DB] load error", e.message); }
}

loadDb();
setInterval(saveDb, 30_000);

// ====================================================
// HELPERS
// ====================================================
function uid(len = 32) { return crypto.randomBytes(len).toString("hex"); }
function now()          { return Math.floor(Date.now() / 1000); }
function ms()           { return Date.now(); }

// custom hash — เหมือนใน ClientLoader
function customHash(value) {
    for (let r = 0; r < 2; r++) {
        const v1 = Number(value % 9915n) + 4;
        let v2 = 0, v3 = 0;
        for (let i = 1; i <= 3; i++) {
            v2 = Number(value % 4155n) + 3;
            if (i % 2 === 1) v2 += 522;
            v3 = Number(value % 9996n) + 1;
            if (v3 % 2 !== 1) v3 *= 3;
        }
        const v4 = Number(value % 9999995n) + 1 + 13729;
        const v5 = Number(value % 1000n);
        const v6 = Number((value / 1000n) % 1000n);
        const v7 = v5 * v6 + v4 + Number(value % BigInt(419824125 - v4 + v5));
        const v8 = Number(value % BigInt(v1 * v2 + 9999)) + 13729;
        value = BigInt(v7 + (v8 + (v5 * v2 + v6)) % 999999 * (v4 + v8 % v3)) % 99999999999n;
    }
    return value;
}

function strHash(s) {
    let h = 0n;
    for (let i = 0; i < s.length; i++) h = (h * 31n + BigInt(s.charCodeAt(i))) % 999999999n;
    return h;
}

// AES-256-GCM encrypt/decrypt
function aesEncrypt(plaintext, key32) {
    const iv  = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key32, "hex"), iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        d:  enc.toString("base64"),
        iv: iv.toString("hex"),
        t:  tag.toString("hex"),
    };
}

function aesDecrypt(d, key32, iv, tag) {
    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(key32, "hex"), Buffer.from(iv, "hex"));
        decipher.setAuthTag(Buffer.from(tag, "hex"));
        return Buffer.concat([decipher.update(Buffer.from(d, "base64")), decipher.final()]).toString("utf8");
    } catch { return null; }
}

function keyExpired(key) {
    if (!key.expiresAt) return false;
    return now() > key.expiresAt;
}

function keyNameGen() {
    const seg = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `RX-${seg()}-${seg()}-${seg()}`;
}

// ====================================================
// RATE LIMITER
// ====================================================
const rateMap = new Map(); // ip+route → { count, resetAt }

function rateLimit(maxReq, windowMs) {
    return (req, res, next) => {
        const key = (req.ip || "?") + req.path;
        const entry = rateMap.get(key);
        const t = ms();
        if (!entry || t > entry.resetAt) {
            rateMap.set(key, { count: 1, resetAt: t + windowMs });
            return next();
        }
        entry.count++;
        if (entry.count > maxReq) {
            return res.status(429).json({ ok: false, e: "rate", message: "Too many requests" });
        }
        next();
    };
}
setInterval(() => {
    const t = ms();
    for (const [k, v] of rateMap) if (t > v.resetAt) rateMap.delete(k);
}, 60_000);

// ====================================================
// AUTH MIDDLEWARE
// ====================================================
function botAuth(req, res, next) {
    if (req.headers["x-bot-secret"] !== BOT_SECRET) {
        return res.status(401).json({ ok: false, message: "Unauthorized" });
    }
    next();
}
function ownerAuth(req, res, next) {
    if (req.headers["x-owner-secret"] !== OWNER_SECRET) {
        return res.status(401).json({ ok: false, message: "Unauthorized" });
    }
    next();
}
function sessionAuth(req, res, next) {
    const token = req.body?.token || req.headers["x-session-token"];
    if (!token || !db.sessions[token]) {
        return res.status(401).json({ ok: false, message: "Invalid session" });
    }
    req.session = db.sessions[token];
    req.token   = token;
    next();
}

// ====================================================
// ROUTES: STATUS
// ====================================================
app.get("/", (_, res) => res.json({ name: "RainX API", status: "running", version: 3 }));
app.get("/health", (_, res) => res.json({ ok: true, uptime: process.uptime() }));
app.get("/ping", (_, res) => res.json({ ok: true, ts: now() }));

// ====================================================
// ROUTES: CONFIG
// ====================================================
app.get("/config", botAuth, (_, res) => res.json({ ok: true, config: db.config }));

app.post("/config", ownerAuth, (req, res) => {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ ok: false, message: "key required" });
    db.config[key] = value;
    saveDb();
    res.json({ ok: true, config: db.config });
});

// ====================================================
// ROUTES: KEYS
// ====================================================
app.get("/keys", botAuth, (_, res) => {
    const list = Object.entries(db.keys).map(([name, k]) => ({
        name,
        active:    !keyExpired(k) && k.active !== false,
        usedBy:    k.usedBy   || null,
        hwid:      k.hwid     || null,
        expiresAt: k.expiresAt || null,
        createdAt: k.createdAt,
        file:      k.file     || null,
        note:      k.note     || null,
    }));
    res.json({ ok: true, keys: list });
});

app.post("/keys/generate", botAuth, rateLimit(30, 60_000), (req, res) => {
    const { duration, file, note, createdBy, amount = 1 } = req.body;
    const count  = Math.min(Math.max(parseInt(amount) || 1, 1), 50);
    const created = [];
    for (let i = 0; i < count; i++) {
        const name = keyNameGen();
        db.keys[name] = {
            active:    true,
            createdAt: now(),
            expiresAt: duration > 0 ? now() + duration * 86400 : null,
            duration:  duration || 0,
            usedBy:    null,
            hwid:      null,
            file:      file  || null,
            note:      note  || null,
            createdBy: createdBy || null,
        };
        created.push(name);
    }
    saveDb();
    res.json({ ok: true, keys: created });
});

app.get("/keys/user/:userId", botAuth, (req, res) => {
    const { userId } = req.params;
    const found = Object.entries(db.keys)
        .filter(([, k]) => k.usedBy === userId)
        .map(([name, k]) => ({ name, active: !keyExpired(k) && k.active !== false, expiresAt: k.expiresAt, file: k.file }));
    res.json({ ok: true, keys: found });
});

app.get("/keys/:keyName", botAuth, (req, res) => {
    const key = db.keys[req.params.keyName];
    if (!key) return res.status(404).json({ ok: false, message: "Key not found" });
    res.json({ ok: true, key: { ...key, name: req.params.keyName } });
});

app.post("/keys/:keyName/redeem", rateLimit(10, 60_000), (req, res) => {
    const { hwid, userId } = req.body;
    const key = db.keys[req.params.keyName];
    if (!key)                          return res.json({ ok: false, e: "key" });
    if (key.active === false)          return res.json({ ok: false, e: "revoked" });
    if (keyExpired(key))               return res.json({ ok: false, e: "exp" });
    if (key.hwid && key.hwid !== hwid) return res.json({ ok: false, e: "hwid" });
    if (!key.hwid) { key.hwid = hwid; key.usedBy = userId; key.redeemedAt = now(); }
    saveDb();
    res.json({ ok: true, file: key.file || null, expiresAt: key.expiresAt });
});

app.delete("/keys/:keyName", botAuth, (req, res) => {
    if (!db.keys[req.params.keyName]) return res.status(404).json({ ok: false });
    delete db.keys[req.params.keyName];
    saveDb();
    res.json({ ok: true });
});

app.post("/keys/:keyName/reset-hwid", botAuth, (req, res) => {
    const key = db.keys[req.params.keyName];
    if (!key) return res.status(404).json({ ok: false, message: "Key not found" });
    key.hwid = null;
    saveDb();
    res.json({ ok: true });
});

app.post("/keys/:keyName/revoke", botAuth, (req, res) => {
    const key = db.keys[req.params.keyName];
    if (!key) return res.status(404).json({ ok: false, message: "Key not found" });
    const usedBy = key.usedBy;
    // kick active session ของ key นี้
    for (const [token, sess] of Object.entries(db.sessions)) {
        if (sess.keyName === req.params.keyName) {
            sess.revoked = true;
            delete db.sessions[token];
        }
    }
    key.active = false;
    key.hwid   = null;
    saveDb();
    res.json({ ok: true, usedBy });
});

// ====================================================
// ROUTES: CDN-CGI CHALLENGE
// step 1: ตรวจ key → สร้าง session_id + aes_key
// ====================================================
app.post("/cdn-cgi/challenge", rateLimit(20, 60_000), (req, res) => {
    const { key, hwid, ts, nonce, fp, exe, place, placeId, jobId, chain } = req.body;
    if (!key || !hwid || !nonce) return res.status(400).json({ ok: false, e: "bad_req" });

    // timestamp skew check (±120s)
    if (Math.abs(now() - (parseInt(ts) || 0)) > 120) return res.json({ ok: false, e: "ts" });

    const keyData = db.keys[key];
    if (!keyData)                           return res.json({ ok: false, e: "key" });
    if (keyData.active === false)           return res.json({ ok: false, e: "key" });
    if (keyExpired(keyData))                return res.json({ ok: false, e: "exp" });
    if (keyData.hwid && keyData.hwid !== hwid) return res.json({ ok: false, e: "hwid" });

    // สร้าง session challenge
    const sessionId  = uid(16);
    const aesKey     = uid(16);  // 32 hex chars = 16 bytes
    const seed       = crypto.randomInt(1000000, 9999999);

    // เก็บ challenge ชั่วคราว (expire 60s)
    db.challenges[nonce] = {
        sessionId,
        aesKey,
        seed,
        keyName: key,
        hwid,
        fp,
        exe:     exe     || "unidentified",
        place:   place   || "unidentified",
        placeId: placeId || "0",
        jobId:   jobId   || "",
        chain:   chain   || "0",
        createdAt: now(),
    };

    // expire challenges เก่า (>60s)
    for (const [n, c] of Object.entries(db.challenges)) {
        if (now() - c.createdAt > 60) delete db.challenges[n];
    }

    res.json({ ok: true, s: sessionId, k: aesKey });
});

// ====================================================
// ROUTES: CDN-CGI TOKEN
// step 2: encrypt activeToken ด้วย aes_key แล้วส่ง
// ====================================================
app.post("/cdn-cgi/token", rateLimit(20, 60_000), (req, res) => {
    const { s, hwid, ts, nonce, chain } = req.body;
    if (!s || !hwid || !nonce) return res.status(400).json({ ok: false, e: "bad_req" });

    const challenge = db.challenges[nonce];
    if (!challenge || challenge.sessionId !== s) return res.json({ ok: false, e: "bad_challenge" });
    if (now() - challenge.createdAt > 60)        return res.json({ ok: false, e: "expired" });
    if (challenge.hwid !== hwid)                 return res.json({ ok: false, e: "hwid" });

    const activeToken = uid(24);
    const seed        = crypto.randomInt(1000000, 9999999);

    // เก็บ session
    db.sessions[activeToken] = {
        keyName:   challenge.keyName,
        hwid:      challenge.hwid,
        fp:        challenge.fp,
        exe:       challenge.exe,
        place:     challenge.place,
        placeId:   challenge.placeId,
        jobId:     challenge.jobId,
        createdAt: now(),
        lastSeen:  now(),
        validated: false,
        revoked:   false,
        seed,
    };

    // set hwid ใน key ถ้ายังไม่มี
    const keyData = db.keys[challenge.keyName];
    if (keyData && !keyData.hwid) {
        keyData.hwid = hwid;
        keyData.redeemedAt = keyData.redeemedAt || now();
    }

    // encrypt payload
    const payload   = JSON.stringify({ ok: true, activeToken, seed });
    const encrypted = aesEncrypt(payload, challenge.aesKey);

    delete db.challenges[nonce];
    saveDb();

    res.json({ ok: true, ...encrypted });
});

// ====================================================
// ROUTES: CDN-CGI VALIDATE
// step 3: verify chain hash ที่ client สร้าง
// ====================================================
app.post("/cdn-cgi/validate", rateLimit(20, 60_000), (req, res) => {
    const { token, hwid, h1, h2, ts } = req.body;
    if (!token) return res.status(400).json({ ok: false, e: "bad_req" });

    const sess = db.sessions[token];
    if (!sess || sess.revoked) return res.json({ ok: false, e: "invalid_token" });
    if (sess.hwid !== hwid)    return res.json({ ok: false, e: "hwid" });
    if (Math.abs(now() - (parseInt(ts) || 0)) > 120) return res.json({ ok: false, e: "ts" });

    // verify h1 (chain hash จาก client — ไม่บังคับ verify ค่า exact เพราะ chain มา client-side)
    // แต่ต้องมีและไม่ว่าง
    if (!h1) return res.json({ ok: false, e: "chain_missing" });

    const seed   = crypto.randomInt(1000000, 9999999);
    // check = customHash(chain + seed) ให้ client verify
    const h1Big  = BigInt(h1) || 0n;
    const check  = String(customHash(h1Big + BigInt(seed)));

    sess.validated = true;
    sess.lastSeen  = now();
    sess.seed      = seed;

    res.json({ ok: true, seed, check });
});

// ====================================================
// ROUTES: CDN-CGI HEARTBEAT
// ====================================================
app.post("/cdn-cgi/heartbeat", rateLimit(60, 60_000), (req, res) => {
    const { token, hwid, ts, ping, check, pingChain } = req.body;
    if (!token) return res.status(400).json({ ok: false, e: "bad_req" });

    const sess = db.sessions[token];
    if (!sess || sess.revoked)   return res.json({ ok: false, alive: false, e: "invalid_token" });
    if (!sess.validated)         return res.json({ ok: false, alive: false, e: "not_validated" });
    if (sess.hwid !== hwid)      return res.json({ ok: false, alive: false, e: "hwid" });

    // timeout: ถ้าไม่ heartbeat 120s ให้ kick
    if (now() - sess.lastSeen > 120) {
        sess.revoked = true;
        delete db.sessions[token];
        saveDb();
        return res.json({ ok: false, alive: false, e: "timeout" });
    }

    const seed    = crypto.randomInt(100000, 9999999);
    const pingN   = BigInt(ping || 0);
    const checkN  = BigInt(check || 0);
    const pongCheck = String(customHash(pingN + checkN + BigInt(seed)));

    sess.lastSeen = now();

    res.json({ ok: true, alive: true, seed, check: pongCheck });
});

// ====================================================
// ROUTES: API/V1 AUTHENTICATE (LuaSync endpoint)
// ====================================================
app.post("/api/v1/authenticate", rateLimit(20, 60_000), (req, res) => {
    const { projectId, key, hwid, fp, ts, nonce, chain } = req.body;
    if (!key || !hwid) return res.status(400).json({ ok: false, error: "bad_req" });

    const keyData = db.keys[key];
    if (!keyData)                              return res.json({ ok: false, error: "invalid_key" });
    if (keyData.active === false)              return res.json({ ok: false, error: "invalid_key" });
    if (keyExpired(keyData))                   return res.json({ ok: false, error: "expired" });
    if (keyData.hwid && keyData.hwid !== hwid) return res.json({ ok: false, error: "hwid_mismatch" });

    const token = uid(16);
    const seed  = crypto.randomInt(1000000, 9999999);

    // เก็บ LuaSync token ชั่วคราว 60s (ใช้ใน challenge cross-verify)
    db.challenges[`ls_${nonce}`] = {
        token, seed, keyName: key, hwid, fp,
        createdAt: now(),
    };

    res.json({ ok: true, token, seed });
});

// ====================================================
// ROUTES: ADMIN
// ====================================================
app.post("/admin/revoke-session", ownerAuth, (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ ok: false });
    if (!db.sessions[token]) return res.status(404).json({ ok: false, reason: "not found" });
    db.sessions[token].revoked = true;
    delete db.sessions[token];
    saveDb();
    res.json({ ok: true });
});

// cleanup expired sessions (ทุก 5 นาที)
setInterval(() => {
    let cleaned = 0;
    for (const [token, sess] of Object.entries(db.sessions)) {
        if (sess.revoked || (now() - sess.lastSeen) > 300) {
            delete db.sessions[token];
            cleaned++;
        }
    }
    if (cleaned) { console.log(`[CLEANUP] removed ${cleaned} dead sessions`); saveDb(); }
}, 5 * 60_000);

// ====================================================
// WEBSOCKET — /cdn-cgi/ws
// ====================================================
const wsClients = new Map(); // token → ws

wss.on("connection", (ws, req) => {
    let wsToken = null;

    ws.on("message", (raw) => {
        try {
            const msg = JSON.parse(raw.toString());

            // PING
            if (msg.op === "PING") {
                const { token, hwid, ts, ping, pong, pingChain } = msg;
                const sess = db.sessions[token];
                if (!sess || sess.revoked || sess.hwid !== hwid) {
                    ws.send(JSON.stringify({ op: "KICK", reason: "invalid_session" }));
                    ws.close();
                    return;
                }
                if (!sess.validated) {
                    ws.send(JSON.stringify({ op: "KICK", reason: "not_validated" }));
                    ws.close();
                    return;
                }
                if (now() - sess.lastSeen > 120) {
                    sess.revoked = true;
                    delete db.sessions[token];
                    ws.send(JSON.stringify({ op: "KICK", reason: "timeout" }));
                    ws.close();
                    return;
                }

                wsToken = token;
                wsClients.set(token, ws);
                sess.lastSeen = now();

                const seed     = crypto.randomInt(100000, 9999999);
                const pingN    = BigInt(ping || 0);
                const pongN    = BigInt(pong || 0);
                const pongHash = String(customHash(pingN + pongN + BigInt(seed)));

                ws.send(JSON.stringify({ op: "PONG", seed, check: pongHash }));
            }
        } catch (e) {
            console.error("[WS] parse error", e.message);
        }
    });

    ws.on("close", () => {
        if (wsToken) wsClients.delete(wsToken);
    });

    ws.on("error", (e) => console.error("[WS] error", e.message));

    // timeout 30s ถ้าไม่ส่ง PING มา
    const timeout = setTimeout(() => {
        if (!wsToken) { ws.close(); }
    }, 30_000);
    ws.once("message", () => clearTimeout(timeout));
});

// ====================================================
// START
// ====================================================
server.listen(PORT, () => {
    console.log(`[RainX] server v3 running on port ${PORT}`);
    console.log(`[DB] keys: ${Object.keys(db.keys).length}`);
});

process.on("SIGINT", () => { saveDb(); process.exit(0); });
process.on("SIGTERM", () => { saveDb(); process.exit(0); });
