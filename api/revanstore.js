import CryptoJS from 'crypto-js';
import admin from 'firebase-admin';

const ADMIN_KEY = process.env.ADMIN_KEY;

if (!admin.apps.length) {
  const key = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  admin.initializeApp({
    credential: admin.credential.cert({ projectId: process.env.FIREBASE_PROJECT_ID, clientEmail: process.env.FIREBASE_CLIENT_EMAIL, privateKey: key }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

const db = admin.database();
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW = 60000;

function checkRateLimit(ip) {
  const now = Date.now();
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const requests = rateLimitMap.get(ip).filter(t => now - t < RATE_LIMIT_WINDOW);
  if (requests.length >= RATE_LIMIT_MAX) return false;
  requests.push(now);
  rateLimitMap.set(ip, requests);
  return true;
}

const requestTimestamps = new Map();
const MIN_REQUEST_DELAY = 800;

function checkRequestDelay(ip, path) {
  if (path === 'login_success' || path === 'login_failed' || path === 'check_blocked') return true;
  const now = Date.now();
  const last = requestTimestamps.get(ip) || 0;
  if (now - last < MIN_REQUEST_DELAY) return false;
  requestTimestamps.set(ip, now);
  return true;
}

async function decryptData(raw) {
  if (!raw) return raw;
  if (raw.data) {
    try {
      const dec = CryptoJS.AES.decrypt(raw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
      return { ...raw, ...JSON.parse(dec) };
    } catch(e) { return raw; }
  }
  return raw;
}

async function isIPBlocked(ip) {
  const snap = await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).once('value');
  const raw = snap.val();
  if (raw?.data) {
    try {
      const dec = CryptoJS.AES.decrypt(raw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
      if (JSON.parse(dec)?.blocked) return true;
    } catch(e) {}
  }
  return false;
}

async function isFPBlocked(fp) {
  const snap = await db.ref('blocked_fp/' + fp).once('value');
  const raw = snap.val();
  if (raw?.data) {
    try {
      const dec = CryptoJS.AES.decrypt(raw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
      if (JSON.parse(dec)?.blocked) return true;
    } catch(e) {}
  }
  return false;
}

async function blockIP(ip) {
  const enc = CryptoJS.AES.encrypt(JSON.stringify({ ip, blocked: true, blocked_at: new Date().toISOString() }), ADMIN_KEY).toString();
  await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).set({ data: enc });
}

async function blockFP(fp) {
  const enc = CryptoJS.AES.encrypt(JSON.stringify({ fingerprint: fp, blocked: true, blocked_at: new Date().toISOString() }), ADMIN_KEY).toString();
  await db.ref('blocked_fp/' + fp).set({ data: enc });
}

async function trackLoginAttempt(ip, fp) {
  const key = ip.replace(/\./g, '_') + '_' + (fp || 'nofp');
  const ref = db.ref('login_attempts/' + key);
  const snap = await ref.once('value');
  const raw = snap.val();
  const now = Date.now();
  let attempts = 0, lastAttempt = 0;
  
  if (raw?.data) {
    try {
      const data = JSON.parse(CryptoJS.AES.decrypt(raw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8));
      attempts = data.count || 0;
      lastAttempt = data.last_attempt || 0;
      
      if (now - lastAttempt > 3600000) {
        await ref.remove();
        const enc = CryptoJS.AES.encrypt(JSON.stringify({ count: 1, last_attempt: now, fingerprint: fp }), ADMIN_KEY).toString();
        await ref.set({ data: enc });
        return 1;
      }
    } catch(e) {}
  }
  
  const newCount = attempts + 1;
  const enc = CryptoJS.AES.encrypt(JSON.stringify({ count: newCount, last_attempt: now, fingerprint: fp }), ADMIN_KEY).toString();
  await ref.set({ data: enc });
  return newCount;
}

async function resetLoginAttempt(ip, fp) {
  await db.ref('login_attempts/' + ip.replace(/\./g, '_') + '_' + (fp || 'nofp')).remove();
}

async function cleanupOldAttempts() {
  const snap = await db.ref('login_attempts').once('value');
  const data = snap.val();
  if (!data) return;
  const now = Date.now();
  for (const key in data) {
    if (data[key]?.data) {
      try {
        const parsed = JSON.parse(CryptoJS.AES.decrypt(data[key].data, ADMIN_KEY).toString(CryptoJS.enc.Utf8));
        if (now - (parsed.last_attempt || 0) > 86400000) await db.ref('login_attempts/' + key).remove();
      } catch(e) {}
    }
  }
}

export default async function handler(req, res) {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  else if (allowedOrigins.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
  
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, X-Fingerprint');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  
  const ip = req.headers['x-forwarded-for'] || 'unknown';
  const fp = req.headers['x-fingerprint'] || '';
  
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Terlalu banyak request. Coba lagi nanti.' });

  try {
    const { path, method, data } = req.body;
    
    if (!checkRequestDelay(ip, path)) return res.status(429).json({ error: 'Request terlalu cepat. Harap tunggu.' });
    if (!path || typeof path !== 'string' || path.length > 200) return res.status(400).json({ error: 'Invalid path' });
    
    const ref = db.ref(path);

    if (path === 'check_blocked' && method === 'POST') {
      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = fp ? await isFPBlocked(fp) : false;
      return res.status(200).json({ blocked: ipBlocked || fpBlocked });
    }

    if (path === 'login' && method === 'POST') {
      if (await isIPBlocked(ip) || (fp && await isFPBlocked(fp))) return res.status(200).json({ blocked: true });
      const snap = await db.ref('users').once('value');
      const users = snap.val();
      for (const key in users) {
        const decryptedUser = await decryptData({ ...users[key], id: key });
        if (decryptedUser.username === data.username && decryptedUser.password === data.password) {
          return res.status(200).json({ success: true, data: { id: key, username: decryptedUser.username, role: decryptedUser.role || 'User', full_name: decryptedUser.full_name || '', expiry_date: decryptedUser.expiry_date || '' } });
        }
      }
      return res.status(200).json({ success: false });
    }

    if (path === 'login_failed' && method === 'POST') {
      const attempts = await trackLoginAttempt(ip, fp);
      await new Promise(r => setTimeout(r, attempts * 500));
      if (attempts >= 5) { await blockIP(ip); if (fp) await blockFP(fp); return res.status(200).json({ blocked: true }); }
      return res.status(200).json({ attempts });
    }

    if (path === 'login_success' && method === 'POST') { await resetLoginAttempt(ip, fp); return res.status(200).json({ success: true }); }
    if (method === 'GET') { const snap = await ref.once('value'); const raw = snap.val(); const result = {}; if (raw) for (const key in raw) { const d = await decryptData({ ...raw[key], id: key }); result[key] = d; result[key].id = key; } return res.status(200).json(result); }
    if (method === 'POST') { const r = ref.push(); await r.set(data); return res.status(200).json({ success: true, id: r.key }); }
    if (method === 'PUT') { await ref.set(data); return res.status(200).json({ success: true }); }
    if (method === 'PATCH') { await ref.update(data); return res.status(200).json({ success: true }); }
    if (method === 'DELETE') { await ref.remove(); return res.status(200).json({ success: true }); }

    return res.status(400).json({ error: 'Invalid method' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}