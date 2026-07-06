import CryptoJS from 'crypto-js';
import admin from 'firebase-admin';

const ADMIN_KEY = process.env.ADMIN_KEY;

if (!admin.apps.length) {
  const key = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: key
    }),
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
  if (path === 'login_success' || path === 'login_failed' || path === 'check_blocked' || 
      path === 'admin/login_success' || path === 'admin/login_failed') return true;
  const now = Date.now();
  const last = requestTimestamps.get(ip) || 0;
  if (now - last < MIN_REQUEST_DELAY) return false;
  requestTimestamps.set(ip, now);
  return true;
}

function encryptResponse(data) {
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), ADMIN_KEY).toString();
  return { encrypted: true, data: encrypted };
}

function decryptFirebaseData(raw) {
  if (!raw) return null;
  if (raw.data) {
    try {
      const dec = CryptoJS.AES.decrypt(raw.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
      return JSON.parse(dec);
    } catch(e) {
      return null;
    }
  }
  return raw;
}

async function isIPBlocked(ip) {
  const snap = await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).once('value');
  const data = decryptFirebaseData(snap.val());
  return data?.blocked || false;
}

async function isFPBlocked(fp) {
  if (!fp) return false;
  const snap = await db.ref('blocked_fp/' + fp).once('value');
  const data = decryptFirebaseData(snap.val());
  return data?.blocked || false;
}

async function blockIP(ip) {
  const enc = CryptoJS.AES.encrypt(JSON.stringify({
    ip: ip,
    blocked: true,
    blocked_at: new Date().toISOString()
  }), ADMIN_KEY).toString();
  await db.ref('blocked_ips/' + ip.replace(/\./g, '_')).set({ data: enc });
}

async function blockFP(fp) {
  if (!fp) return;
  const enc = CryptoJS.AES.encrypt(JSON.stringify({
    fingerprint: fp,
    blocked: true,
    blocked_at: new Date().toISOString()
  }), ADMIN_KEY).toString();
  await db.ref('blocked_fp/' + fp).set({ data: enc });
}

async function trackLoginAttempt(ip, fp) {
  const key = ip.replace(/\./g, '_') + '_' + (fp || 'nofp');
  const ref = db.ref('login_attempts/' + key);
  const snap = await ref.once('value');
  const data = decryptFirebaseData(snap.val());
  const now = Date.now();
  
  if (data && data.last_attempt) {
    if (now - data.last_attempt > 3600000) {
      await ref.remove();
      const enc = CryptoJS.AES.encrypt(JSON.stringify({ count: 1, last_attempt: now, fingerprint: fp }), ADMIN_KEY).toString();
      await ref.set({ data: enc });
      return 1;
    }
  }
  
  const newCount = (data?.count || 0) + 1;
  const enc = CryptoJS.AES.encrypt(JSON.stringify({ count: newCount, last_attempt: now, fingerprint: fp }), ADMIN_KEY).toString();
  await ref.set({ data: enc });
  return newCount;
}

async function resetLoginAttempt(ip, fp) {
  await db.ref('login_attempts/' + ip.replace(/\./g, '_') + '_' + (fp || 'nofp')).remove();
}

async function cleanupOldAttempts() {
  try {
    const snap = await db.ref('login_attempts').once('value');
    const data = snap.val();
    if (!data) return;
    const now = Date.now();
    for (const key in data) {
      if (data[key]?.data) {
        try {
          const parsed = JSON.parse(CryptoJS.AES.decrypt(data[key].data, ADMIN_KEY).toString(CryptoJS.enc.Utf8));
          if (now - (parsed.last_attempt || 0) > 86400000) {
            await db.ref('login_attempts/' + key).remove();
          }
        } catch(e) {}
      }
    }
  } catch(e) {}
}

export default async function handler(req, res) {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (allowedOrigins.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, X-Fingerprint');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
  const fp = req.headers['x-fingerprint'] || '';
  
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Terlalu banyak request. Coba lagi nanti.' });
  }
  
  if (Math.random() < 0.05) {
    cleanupOldAttempts().catch(() => {});
  }

  try {
    const body = req.body;
    if (!body) return res.status(400).json({ error: 'No data' });

    const path = body.path;
    const method = body.method || 'GET';
    const data = body.data || null;
    
    if (!path) return res.status(400).json({ error: 'Invalid request' });
    
    if (!checkRequestDelay(ip, path)) {
      return res.status(429).json({ error: 'Request terlalu cepat. Harap tunggu.' });
    }
    
    if (typeof path !== 'string' || path.length > 200) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    
    const ref = db.ref(path);

    if (path === 'check_blocked' && method === 'POST') {
      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = await isFPBlocked(fp);
      return res.status(200).json({ blocked: ipBlocked || fpBlocked });
    }

    if ((path === 'login_failed' || path === 'admin/login_failed') && method === 'POST') {
      const attempts = await trackLoginAttempt(ip, fp);
      await new Promise(r => setTimeout(r, Math.min(attempts * 500, 3000)));
      
      if (attempts >= 5) {
        await blockIP(ip);
        if (fp) await blockFP(fp);
        return res.status(200).json(encryptResponse({ blocked: true, attempts }));
      }
      
      return res.status(200).json(encryptResponse({ attempts, remaining: 5 - attempts }));
    }

    if ((path === 'login_success' || path === 'admin/login_success') && method === 'POST') {
      await resetLoginAttempt(ip, fp);
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (path === 'login' && method === 'POST') {
      const ipBlocked = await isIPBlocked(ip);
      const fpBlocked = await isFPBlocked(fp);
      
      if (ipBlocked || fpBlocked) {
        return res.status(200).json({ blocked: true });
      }
      
      if (!data || !data.username || !data.password) {
        return res.status(200).json({ success: false, message: 'Invalid credentials' });
      }
      
      const snap = await db.ref('users').once('value');
      const users = snap.val();
      
      if (!users) {
        return res.status(200).json({ success: false, message: 'No users found' });
      }
      
      for (const key in users) {
        const decryptedUser = decryptFirebaseData(users[key]);
        if (decryptedUser && 
            decryptedUser.username === data.username && 
            decryptedUser.password === data.password) {
          
          return res.status(200).json({
            success: true,
            data: {
              id: key,
              username: decryptedUser.username,
              password: data.password,
              role: decryptedUser.role || 'Operator',
              full_name: decryptedUser.full_name || decryptedUser.username,
              expiry_date: decryptedUser.expiry_date || ''
            }
          });
        }
      }
      
      return res.status(200).json({ success: false, message: 'Username atau password salah' });
    }

    if (method === 'GET') {
      const snap = await ref.once('value');
      const raw = snap.val();
      const result = {};
      
      if (raw) {
        for (const key in raw) {
          const decrypted = decryptFirebaseData(raw[key]);
          if (decrypted) {
            result[key] = decrypted;
            result[key].id = key;
          } else if (raw[key]) {
            result[key] = raw[key];
            result[key].id = key;
          }
        }
      }
      
      return res.status(200).json(result);
    }

    if (method === 'POST') {
      const enc = CryptoJS.AES.encrypt(JSON.stringify(data), ADMIN_KEY).toString();
      const newRef = ref.push();
      await newRef.set({ data: enc });
      return res.status(200).json(encryptResponse({ success: true, id: newRef.key }));
    }

    if (method === 'PUT') {
      const enc = CryptoJS.AES.encrypt(JSON.stringify(data), ADMIN_KEY).toString();
      await ref.set({ data: enc });
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (method === 'PATCH') {
      const snap = await ref.once('value');
      const existing = decryptFirebaseData(snap.val());
      const merged = Object.assign({}, existing || {}, data);
      const enc = CryptoJS.AES.encrypt(JSON.stringify(merged), ADMIN_KEY).toString();
      await ref.update({ data: enc });
      return res.status(200).json(encryptResponse({ success: true }));
    }

    if (method === 'DELETE') {
      await ref.remove();
      return res.status(200).json(encryptResponse({ success: true }));
    }

    return res.status(400).json({ error: 'Invalid method' });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: error.message || 'Internal Server Error' });
  }
}