
const bcrypt = require('bcryptjs');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const session = require('express-session');
const pg = require('pg');
const crypto = require('crypto');
const multer = require('multer');
const { spawn } = require('child_process');
const ffmpegPath = require('ffmpeg-static');
const webpush = require('web-push');
require('dotenv').config();
if (!process.env.SESSION_SECRET || !process.env.SESSION_SECRET.trim()) {
  throw new Error('SESSION_SECRET is required. Set it in the environment before starting the server.');
}
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
const vapidSubject = process.env.VAPID_SUBJECT;

if (vapidPublicKey && vapidPrivateKey && vapidSubject) {
  webpush.setVapidDetails(
    vapidSubject,
    vapidPublicKey,
    vapidPrivateKey
  );
} else {
  console.warn('Web Push VAPID environment variables are not configured.');
}
async function sendIncomingWhatsAppPush(clientId, phone, message) {
  try {
    const result = await pool.query(
      `SELECT id, subscription
       FROM whatsapp_push_subscriptions
       WHERE (
         ($1::integer IS NULL AND role = 'admin' AND client_id IS NULL)
         OR
         ($1::integer IS NOT NULL AND role <> 'admin' AND client_id = $1)
       )`,
      [clientId]
    );

    const payload = JSON.stringify({
      title: 'New WhatsApp message',
      body: `From ${phone}: ${message}`,
      url: '/whatsapp'
    });

    await Promise.allSettled(
      result.rows.map(async (row) => {
        try {
          await webpush.sendNotification(
            row.subscription,
            payload
          );
        } catch (err) {
          if (err.statusCode === 404 || err.statusCode === 410) {
            await pool.query(
              'DELETE FROM whatsapp_push_subscriptions WHERE id = $1',
              [row.id]
            );
          } else {
            console.error('WhatsApp push notification failed:', err.message);
          }
        }
      })
    );
  } catch (err) {
    console.error('WhatsApp push error:', err.message);
  }
}
const { Pool } = pg;
const app = express();
app.use(helmet({
  contentSecurityPolicy: false
}));
app.get('/service-worker.js', function (req, res) {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Service-Worker-Allowed', '/');

  res.send(`
    self.addEventListener('push', function (event) {
      let data = {};

      try {
        data = event.data ? event.data.json() : {};
      } catch (err) {
        data = {
          title: 'New WhatsApp message',
          body: 'You have a new message.'
        };
      }

      event.waitUntil(
        self.registration.showNotification(
          data.title || 'New WhatsApp message',
          {
            body: data.body || 'You have a new message.',
            icon: '/favicon.ico',
            data: {
              url: data.url || '/whatsapp'
            }
          }
        )
      );
    });

    self.addEventListener('notificationclick', function (event) {
      event.notification.close();

      const url = event.notification.data?.url || '/whatsapp';

      event.waitUntil(
        clients.matchAll({
          type: 'window',
          includeUncontrolled: true
        }).then(function (windows) {
          for (const windowClient of windows) {
            if (windowClient.url.startsWith(self.location.origin)) {
              return windowClient.focus().then(function () {
                return windowClient.navigate(url);
              });
            }
          }

          return clients.openWindow(url);
        })
      );
    });
  `);
});
const PORT = process.env.PORT || 3000;
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again after 15 minutes.',
  skipSuccessfulRequests: true
});
const whatsappUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 16 * 1024 * 1024
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = [
  'image/jpeg',
  'image/png',
  'audio/aac',
  'audio/mp4',
  'audio/mpeg',
  'audio/amr',
  'audio/ogg',
  'audio/webm',
  'audio/webm;codecs=opus',
  'audio/ogg;codecs=opus'
];
    if (allowedTypes.includes(file.mimetype)) {
      return cb(null, true);
    }

    cb(new Error('Only JPG, PNG, and supported audio files are allowed.'));
  }
});

app.set('trust proxy', 1);

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL missing. Add it on Render Environment Variables.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});
const PgSession = require('connect-pg-simple')(session);

app.use(express.urlencoded({ extended: true }));

app.use(express.json({
  verify: function (req, res, buf) {
    if (req.originalUrl === '/webhook/whatsapp') {
      req.rawBody = Buffer.from(buf);
    }
  }
}));

app.get('/api/push/public-key', function (req, res) {
  if (!vapidPublicKey) {
    return res.status(503).json({
      success: false,
      error: 'Web Push public key is not configured'
    });
  }

  return res.json({
    success: true,
    publicKey: vapidPublicKey
  });
});
async function requireApiKey(req, res, next) {
  try {
    const apiKey = req.headers['x-api-key'];

    if (typeof apiKey !== 'string' || !apiKey.trim()) {
      return res.status(401).json({
        success: false,
        error: 'API key is required'
      });
    }

    const validApiKey = process.env.CRM_API_KEY;

          // Global API key: admin-level API access
    if (
      validApiKey &&
      apiKey.length === validApiKey.length &&
      crypto.timingSafeEqual(
        Buffer.from(apiKey),
        Buffer.from(validApiKey)
      )
    ) {
      req.apiClientId = null;
      req.apiRole = 'admin';
      return next();
    }
    // Client-specific API key
    const result = await pool.query(
      `SELECT id, status FROM clients WHERE api_key = $1`,
      [apiKey]
    );

    if (!result.rows[0]) {
      return res.status(401).json({
        success: false,
        error: 'Invalid API key'
      });
    }

    const client = result.rows[0];

    if (client.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: 'Client account is inactive'
      });
    }

    req.apiClientId = client.id;
    req.apiRole = 'client';

    return next();
  } catch (err) {
    console.error('API authentication error:', err);

    return res.status(500).json({
      success: false,
      error: 'API authentication failed'
    });
  }
}
app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));
function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function selected(a, b) {
  return String(a ?? '') === String(b ?? '') ? 'selected' : '';
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  if (req.session.user.role !== 'admin') {
    return res.status(403).send(
      page(
        'Access Denied',
        '<div class="card"><h2>Access denied</h2><p>Only admin can access this section.</p></div>',
        '',
        req.session.user.username
      )
    );
  }

  next();
}function requireStaffOrAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  if (
    req.session.user.role !== 'admin' &&
    req.session.user.role !== 'staff'
  ) {
    return res.status(403).send(
      page(
        'Access Denied',
        '<div class="card"><h2>Access denied</h2><p>You do not have permission for this action.</p></div>',
        '',
        req.session.user.username
      )
    );
  }

  next();
}
app.post('/api/push/subscribe', requireLogin, async function (req, res) {
  try {
    const user = req.session.user;
    const subscription = req.body.subscription;

    if (
      !subscription ||
      typeof subscription.endpoint !== 'string' ||
      !subscription.endpoint.trim() ||
      !subscription.keys ||
      typeof subscription.keys.p256dh !== 'string' ||
      typeof subscription.keys.auth !== 'string'
    ) {
      return res.status(400).json({
        success: false,
        error: 'Invalid push subscription'
      });
    }

    const clientId =
      user.role === 'admin' ? null : user.client_id;

    if (user.role !== 'admin' && !clientId) {
      return res.status(403).json({
        success: false,
        error: 'Client account is not configured'
      });
    }

    await pool.query(
      `INSERT INTO whatsapp_push_subscriptions
        (user_id, role, client_id, endpoint, subscription, updated_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, NOW())
       ON CONFLICT (endpoint)
       DO UPDATE SET
         user_id = EXCLUDED.user_id,
         role = EXCLUDED.role,
         client_id = EXCLUDED.client_id,
         subscription = EXCLUDED.subscription,
         updated_at = NOW()`,
      [
        user.id,
        user.role,
        clientId,
        subscription.endpoint,
        JSON.stringify(subscription)
      ]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('Push subscription save failed:', err.message);

    return res.status(500).json({
      success: false,
      error: 'Could not save push subscription'
    });
  }
});
function page(title, content, active, role, displayName = '') {
      const nav = [    ['/', 'Dashboard', 'dashboard'],
    ['/customers', 'Customers', 'customers'],
    ['/leads', 'Leads', 'leads'],
    ['/followups', 'Follow-ups', 'followups'],
    ['/reports', 'Reports', 'reports'],
    ['/api-info', 'API', 'api'],
    ['/whatsapp', 'WhatsApp Chat', 'whatsapp']
  ];
if (role === 'admin') {
  nav.push(['/clients', 'Clients', 'clients']);
}
  let links = '';

  for (const item of nav) {    links +=
      '<a class="nav-link ' +
      (active === item[2] ? 'active' : '') +
      '" href="' +
      item[0] +
      '">' +
      item[1] +
      '</a>';
  }

  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} - CRM</title>

<style>
*{
  box-sizing:border-box;
}

body{
  margin:0;
  font-family:Arial,Helvetica,sans-serif;
  background:#0b1020;
  color:#f4f7fb;
}

a{
  color:inherit;
  text-decoration:none;
}

.layout{
  display:flex;
  min-height:100vh;
}

.sidebar{
  width:230px;
  background:#11182b;
  border-right:1px solid #26304a;
  padding:22px 14px;
  position:fixed;
  left:0;
  top:0;
  bottom:0;
}

.logo{
  font-size:24px;
  font-weight:800;
  padding:8px 12px 25px;
}

.logo span{
  color:#6ea8ff;
}

.nav-link{
  display:block;
  padding:12px 14px;
  border-radius:10px;
  margin:5px 0;
  color:#aeb8cc;
}

.nav-link:hover,
.nav-link.active{
  background:#1d2945;
  color:#fff;
}

.main{
  margin-left:230px;
  width:calc(100% - 230px);
  padding:25px;
}

.topbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:15px;
  margin-bottom:25px;
}

.topbar h1{
  margin:0;
  font-size:28px;
}

.user-box{
  background:#151e34;
  padding:10px 15px;
  border:1px solid #293550;
  border-radius:10px;
}

.grid{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:15px;
}

.grid-2{
  display:grid;
  grid-template-columns:repeat(2,1fr);
  gap:18px;
}

.card{
  background:#11182b;
  border:1px solid #26304a;
  border-radius:15px;
  padding:20px;
  margin-bottom:18px;
}

.stat{
  font-size:30px;
  font-weight:800;
  margin-top:8px;
}

.muted{
  color:#8f9bb2;
}

table{
  width:100%;
  border-collapse:collapse;
}

th,td{
  padding:12px 10px;
  border-bottom:1px solid #26304a;
  text-align:left;
}

th{
  color:#9ca9c1;
  font-size:13px;
}

input,
select,
textarea{
  width:100%;
  padding:11px 12px;
  border-radius:9px;
  border:1px solid #303d59;
  background:#0c1325;
  color:#fff;
  outline:none;
}

textarea{
  min-height:90px;
  resize:vertical;
}

input:focus,
select:focus,
textarea:focus{
  border-color:#6ea8ff;
}

.form-grid{
  display:grid;
  grid-template-columns:repeat(2,1fr);
  gap:14px;
}

.form-group{
  margin-bottom:14px;
}

.form-group label{
  display:block;
  margin-bottom:7px;
  color:#aeb8cc;
  font-size:14px;
}

.btn{
  display:inline-block;
  border:0;
  padding:10px 15px;
  border-radius:9px;
  cursor:pointer;
  background:#3478f6;
  color:#fff;
  font-weight:700;
}

.btn:hover{
  opacity:.9;
}

.btn-danger{
  background:#d94343;
}

.btn-green{
  background:#198754;
}

.btn-gray{
  background:#34405b;
}

.actions{
  display:flex;
  gap:7px;
  flex-wrap:wrap;
}

.badge{
  display:inline-block;
  padding:5px 9px;
  border-radius:20px;
  background:#253452;
  font-size:12px;
}

.search-row{
  display:grid;
  grid-template-columns:2fr 1fr 1fr auto;
  gap:10px;
  margin-bottom:18px;
}

.bar{
  height:9px;
  background:#202b44;
  border-radius:20px;
  overflow:hidden;
}

.bar span{
  display:block;
  height:100%;
  background:#4d8dff;
}

.quick{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:12px;
}

.quick a{
  background:#18233b;
  border:1px solid #2b3956;
  padding:18px;
  border-radius:12px;
}

.login-page{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
}

.login-box{
  width:100%;
  max-width:400px;
  background:#11182b;
  border:1px solid #26304a;
  padding:30px;
  border-radius:18px;
}

.login-box h1{
  margin-top:0;
}

.alert{
  background:#42202a;
  border:1px solid #7c3342;
  padding:12px;
  border-radius:9px;
  margin-bottom:15px;
}

.success{
  background:#123d2c;
  border:1px solid #1f7953;
}
.quick-actions,
.status-box,
.today-box {
  background:#111827;
  border:1px solid #1f2937;
  border-radius:16px;
  padding:20px;
  margin-bottom:20px;
  box-shadow:0 10px 30px rgba(0,0,0,.12);
}

.quick-actions h2,
.status-box h2,
.today-box h2 {
  margin-top:0;
  margin-bottom:16px;
}

.action-buttons {
  display:flex;
  gap:12px;
  flex-wrap:wrap;
}

.action-btn {
  display:inline-block;
  padding:11px 16px;
  border-radius:10px;
  text-decoration:none;
  color:white;
  background:#2563eb;
  font-weight:700;
}

.action-btn:hover {
  opacity:.9;
}

.status-item {
  display:flex;
  justify-content:space-between;
  gap:15px;
  padding:13px 0;
  border-bottom:1px solid #1f2937;
}

.status-item:last-child {
  border-bottom:0;
}

.status-item span {
  color:#cbd5e1;
}

.status-item strong {
  color:#22c55e;
}

.today-box p {
  color:#94a3b8;
  margin-bottom:16px;
}
@media(max-width:900px){
  .sidebar{
    position:static;
    width:100%;
    height:auto;
    border-right:0;
    border-bottom:1px solid #26304a;
  }

  .layout{
    display:block;
  }

  .main{
    margin-left:0;
    width:100%;
  }

  .grid{
    grid-template-columns:repeat(2,1fr);
  }

  .grid-2{
    grid-template-columns:1fr;
  }

  .search-row{
    grid-template-columns:1fr;
  }
}


@media (max-width: 600px) {
  .layout {
    display: block;
    min-height: 100vh;
   padding-bottom: calc(100px + env(safe-area-inset-bottom));
  }

  .sidebar {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 0;
    top: auto;
    z-index: 1000;
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: flex-start;
    gap: 5px;
    width: 100%;
    padding: 9px 8px;
    margin: 0;
    overflow-x: auto;
    overflow-y: hidden;
    white-space: nowrap;
    background: #07162e;
    border-top: 1px solid #243c60;
    box-shadow: 0 -5px 20px rgba(0, 0, 0, 0.25);
    -webkit-overflow-scrolling: touch;
  }

  .logo {
    display: none;
  }

  .sidebar .nav-link {
    display: flex;
    flex: 0 0 auto;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    padding: 10px 12px;
    margin: 0;
    border-radius: 12px;
    font-size: 12px;
    white-space: nowrap;
  }

  .sidebar .nav-link:hover,
  .sidebar .nav-link.active {
    background: #1458c8;
    color: #fff;
  }

  .main {
    width: 100%;
    min-width: 0;
    margin-left: 0;
    padding: 14px;
    padding-bottom: 24px;
  }

  .topbar {
    align-items: center;
    flex-direction: row;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 18px;
  }

  .topbar h1 {
    font-size: 22px;
    overflow-wrap: anywhere;
  }

  .user-box {
    max-width: 100%;
    overflow-wrap: anywhere;
  }

  .grid,
  .form-grid,
  .quick,
  .grid-2 {
    grid-template-columns: minmax(0, 1fr);
  }

  .card {
    padding: 15px;
    border-radius: 16px;
  }

  input,
  select,
  textarea {
    box-sizing: border-box;
    width: 100%;
    max-width: 100%;
    min-width: 0;
    font-size: 16px;
  }

  .search-row {
    grid-template-columns: minmax(0, 1fr);
  }

  .actions,
  .action-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .table-wrap {
    max-width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }

  table {
    font-size: 13px;
    min-width: 520px;
  }

  th,
  td {
    padding: 9px 7px;
  }

  .login-box {
    padding: 22px;
  }
}
</style>
</head>

<body>

<div class="layout">

<aside class="sidebar">
  <div class="logo">My<span>CRM</span></div>
  ${links}
  <a class="nav-link" href="/logout">Logout</a>
</aside>

<main class="main">

<div class="topbar">
  <h1>${esc(title)}</h1>
  <div class="user-box">
  ${role === 'admin' ? 'Ã°Å¸â€™â€“ Vipin_0_6 Ã°Å¸â€“Â¤' : 'Ã¢ËœÂ Ã¯Â¸ vipin_B2B Ã¢Å¡Â Ã¯Â¸'}
</div>

<button
  type="button"
  class="btn"
  id="enablePushNotifications"
  style="margin-left:10px;"
>
  Enable Notifications
</button>
</div>

${content}

</main>
</div>
<script>
(function () {
  const button = document.getElementById('enablePushNotifications');

  if (!button) return;

  button.addEventListener('click', async function () {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      alert('Push notifications are not supported by this browser.');
      return;
    }

    if (!window.isSecureContext) {
      alert('Notifications require HTTPS or localhost.');
      return;
    }

    try {
      button.disabled = true;
      button.textContent = 'Enabling...';

      const permission = await Notification.requestPermission();

      if (permission !== 'granted') {
        alert('Notification permission was not granted.');
        return;
      }

      const keyResponse = await fetch('/api/push/public-key');

      if (!keyResponse.ok) {
        throw new Error('Could not load the public key.');
      }

      const keyData = await keyResponse.json();

      function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
          .replace(/-/g, '+')
          .replace(/_/g, '/');

        const raw = window.atob(base64);
        return Uint8Array.from(raw, char => char.charCodeAt(0));
      }

      const registration = await navigator.serviceWorker.register('/service-worker.js');

      let subscription = await registration.pushManager.getSubscription();

      if (!subscription) {
        subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(keyData.publicKey)
        });
      }

      const saveResponse = await fetch('/api/push/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          subscription: subscription
        })
      });

      const saveData = await saveResponse.json();

      if (!saveResponse.ok || !saveData.success) {
        throw new Error(saveData.error || 'Could not save subscription.');
      }

      button.textContent = 'Notifications Enabled';
      alert('Push notifications enabled successfully.');
    } catch (error) {
      console.error('Push notification setup failed:', error);
      alert('Could not enable notifications: ' + error.message);
    } finally {
      if (button.textContent !== 'Notifications Enabled') {
        button.textContent = 'Enable Notifications';
      }
      button.disabled = false;
    }
  });
})();
</script>
</body>
</html>
`;
}

const sourceOptions = [
  'WhatsApp',
  'Website',
  'Facebook Ads',
  'Instagram',
  'Google Ads',
  'Referral',
  'Other'
];

const statusOptions = [
  'New',
  'Contacted',
  'Interested',
  'Follow-up',
  'Converted',
  'Lost'
];

async function setupDatabase() {

await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'staff',
      client_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )
`);

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS client_id INTEGER
`);
await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS client_id INTEGER
`);

// =========================
// MULTI-CLIENT SYSTEM
// =========================

await pool.query(`
  CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(150),
    phone VARCHAR(50),
    status VARCHAR(30) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
  )
`);

await pool.query(`
  ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS api_key VARCHAR(255)
`);
await pool.query(`
  ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS website_url TEXT
`);

await pool.query(`
  ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS whatsapp_auto_reply_message TEXT
`);
await pool.query(`
  CREATE TABLE IF NOT EXISTS whatsapp_auto_reply_sent (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL,
    phone_number_id VARCHAR(100) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    sent_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (client_id, phone_number_id, phone)
  )
`);
const clientsWithoutApiKey = await pool.query(
  `SELECT id FROM clients WHERE api_key IS NULL`
);

for (const client of clientsWithoutApiKey.rows) {

  const apiKey = crypto.randomBytes(32).toString('hex');

  await pool.query(
    `UPDATE clients
     SET api_key=$1
     WHERE id=$2`,
    [
      apiKey,
      client.id
    ]
  );

}

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'staff'
  `);



  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,
      client_id INTEGER,
      name VARCHAR(150) NOT NULL,
      phone VARCHAR(50),
      email VARCHAR(150),
      address TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
await pool.query(`
    ALTER TABLE customers
    ADD COLUMN IF NOT EXISTS phone VARCHAR(50)
  `);
  await pool.query(`
    ALTER TABLE customers
    ADD COLUMN IF NOT EXISTS email VARCHAR(150)
  `);
 await pool.query(`
    ALTER TABLE customers
    ADD COLUMN IF NOT EXISTS address TEXT
  `);

await pool.query(`
  ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS client_id INTEGER
`);


  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id SERIAL PRIMARY KEY,
      client_id INTEGER,
      name VARCHAR(150) NOT NULL,
      phone VARCHAR(50),
      email VARCHAR(150),
      source VARCHAR(100),
      status VARCHAR(50) DEFAULT 'New',
      follow_up DATE,
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS phone VARCHAR(50)
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS email VARCHAR(150)
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS source VARCHAR(100)
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'New'
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up DATE
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS notes TEXT
  `);

await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS client_id INTEGER
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up_completed BOOLEAN NOT NULL DEFAULT FALSE
  `);


const adminPassword = process.env.ADMIN_PASSWORD;

if (!adminPassword) {
  throw new Error('ADMIN_PASSWORD environment variable is required');
}

const hashedAdminPassword = await bcrypt.hash(adminPassword, 12);

if (process.env.ADMIN_PASSWORD_RESET === 'true') {
  await pool.query(
    `INSERT INTO users(username, password, role)
     VALUES($1, $2, $3)
     ON CONFLICT(username)
     DO UPDATE SET password = EXCLUDED.password`,
    ['admin', hashedAdminPassword, 'admin']
  );
} else {
  await pool.query(
    `INSERT INTO users(username, password, role)
     VALUES($1, $2, $3)
     ON CONFLICT(username) DO NOTHING`,
    ['admin', hashedAdminPassword, 'admin']
  );
}
await pool.query(`
    CREATE TABLE IF NOT EXISTS whatsapp_messages (
      id SERIAL PRIMARY KEY,
      phone VARCHAR(50) NOT NULL,
      message TEXT,
      direction VARCHAR(20) NOT NULL,
      whatsapp_message_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS client_id INTEGER
`);
await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS phone_number_id VARCHAR(100)
`);
await pool.query(`
  CREATE UNIQUE INDEX IF NOT EXISTS whatsapp_messages_incoming_unique
  ON whatsapp_messages (
    client_id,
    phone_number_id,
    whatsapp_message_id
  ) NULLS NOT DISTINCT
  WHERE direction = 'incoming'
    AND whatsapp_message_id IS NOT NULL
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS media_type VARCHAR(20)
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS media_id VARCHAR(255)
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS media_mime_type VARCHAR(100)
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS delivery_status VARCHAR(30) DEFAULT 'accepted'
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS delivery_error TEXT
`);

await pool.query(`
  ALTER TABLE whatsapp_messages
  ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMP
`);


await pool.query(`
  CREATE TABLE IF NOT EXISTS client_whatsapp_settings (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL UNIQUE
      REFERENCES clients(id) ON DELETE CASCADE,
    phone_number_id VARCHAR(100) NOT NULL,
    display_phone_number VARCHAR(50),
    access_token TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )
`);
await pool.query(`
  CREATE TABLE IF NOT EXISTS whatsapp_contacts (
    id SERIAL PRIMARY KEY,
    client_id INTEGER,
    phone_number_id VARCHAR(100) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    name VARCHAR(200),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (client_id, phone_number_id, phone)
  )
`);
await pool.query(`
  CREATE UNIQUE INDEX IF NOT EXISTS whatsapp_contacts_global_unique_idx
  ON whatsapp_contacts (phone_number_id, phone)
  WHERE client_id IS NULL
`);
await pool.query(`
  CREATE TABLE IF NOT EXISTS whatsapp_push_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(30) NOT NULL,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE,
    subscription JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS whatsapp_push_subscriptions_account_idx
  ON whatsapp_push_subscriptions (role, client_id)
`);
console.log('Database setup completed.');
}

/* LOGIN */

app.get('/login', function(req, res) {

  if (req.session.user) {
    return res.redirect('/');
  }

  const error = req.query.error
    ? '<div class="alert">Invalid username or password.</div>'
    : '';

  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CRM Login</title>

<style>
body{
  margin:0;
  background:#0b1020;
  color:white;
  font-family:Arial,sans-serif;
}

.login{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
}

.box{
  width:100%;
  max-width:400px;
  background:#11182b;
  border:1px solid #293550;
  border-radius:18px;
  padding:30px;
}

input{
  width:100%;
  box-sizing:border-box;
  padding:12px;
  margin:8px 0 15px;
  background:#0c1325;
  border:1px solid #303d59;
  color:white;
  border-radius:8px;
}

button{
  width:100%;
  padding:12px;
  border:0;
  border-radius:8px;
  background:#3478f6;
  color:white;
  font-weight:bold;
  cursor:pointer;
}

.alert{
  background:#42202a;
  border:1px solid #7c3342;
  padding:12px;
  border-radius:8px;
  margin-bottom:15px;
}
</style>
</head>

<body>
<div class="login">
<div class="box">

<h1>MyCRM</h1>
<p>Admin Login</p>

${error}

<form method="POST" action="/login">

<label>Username</label>
<input name="username" required>

<label>Password</label>
<input name="password" type="password" required>

<button type="submit">Login</button>

</form>

</div>
</div>
</body>
</html>
`);
});

app.post('/login', loginLimiter, async function(req, res) {
   try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1',
      [username]
    );

    const user = result.rows[0];

    if (!user || !password) {
      return res.redirect('/login?error=1');
    }

    let passwordValid = false;
    const storedPassword = String(user.password || '');

    if (
      storedPassword.startsWith('$2a$') ||
      storedPassword.startsWith('$2b$') ||
      storedPassword.startsWith('$2y$')
    ) {
      passwordValid = await bcrypt.compare(
        password,
        storedPassword
      );
    } else {
      passwordValid = password === storedPassword;

      if (passwordValid) {
        const hashedPassword = await bcrypt.hash(password, 12);

        await pool.query(
          'UPDATE users SET password=$1 WHERE id=$2 AND password=$3',
          [hashedPassword, user.id, storedPassword]
        );
      }
    }

    if (!passwordValid) {
      return res.redirect('/login?error=1');
    }

          if (user.role === 'client') {
      const clientResult = await pool.query(
        'SELECT status FROM clients WHERE id=$1',
        [user.client_id]
      );

      if (
        !clientResult.rows[0] ||
        clientResult.rows[0].status !== 'active'
      ) {
        return res.redirect('/login?error=1');
      }
    }
    req.session.regenerate(function(err) {
      if (err) {
        console.error('Session regenerate error:', err);
        return res.redirect('/login?error=1');
      }

     req.session.user = {
  id: user.id,
  username: user.username,
  role: user.role,
  client_id: user.client_id
};

      req.session.save(function(err) {

        if (err) {
          console.error('Session save error:', err);
          return res.redirect('/login?error=1');
        }

        res.redirect('/');
      });
    });

  } catch (err) {

    console.error('Login error:', err);
    res.redirect('/login?error=1');
  }
});


app.get('/logout', function(req, res) {
  req.session.destroy(function(err) {
    res.clearCookie('connect.sid', {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });

    if (err) {
      console.error('Logout session destruction failed:', err);
      return res.status(500).send('Logout failed. Please try again.');
    }

    return res.redirect('/login');
  });
});


/* ANDROID DASHBOARD API */
app.get('/api/mobile/dashboard', async function(req, res) {
  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const isAdmin = user.role === 'admin';
    const clientId = user.client_id;

    const [customersResult, leadsResult, pendingResult, recentLeadsResult] =
      await Promise.all([
        pool.query(
          isAdmin
            ? 'SELECT COUNT(*)::int AS count FROM customers'
            : 'SELECT COUNT(*)::int AS count FROM customers WHERE client_id=$1',
          isAdmin ? [] : [clientId]
        ),

        pool.query(
          isAdmin
            ? 'SELECT COUNT(*)::int AS count FROM leads'
            : 'SELECT COUNT(*)::int AS count FROM leads WHERE client_id=$1',
          isAdmin ? [] : [clientId]
        ),

        pool.query(
          isAdmin
            ? `SELECT COUNT(*)::int AS count
               FROM leads
               WHERE follow_up IS NOT NULL
               AND follow_up >= CURRENT_DATE`
            : `SELECT COUNT(*)::int AS count
               FROM leads
               WHERE follow_up IS NOT NULL
               AND follow_up >= CURRENT_DATE
               AND client_id=$1`,
          isAdmin ? [] : [clientId]
        ),

        pool.query(
          isAdmin
            ? `SELECT id, name, phone, source, status, follow_up
               FROM leads
               ORDER BY id DESC
               LIMIT 10`
            : `SELECT id, name, phone, source, status, follow_up
               FROM leads
               WHERE client_id=$1
               ORDER BY id DESC
               LIMIT 10`,
          isAdmin ? [] : [clientId]
        )
      ]);

    return res.json({
      success: true,
      customers: customersResult.rows[0].count,
      leads: leadsResult.rows[0].count,
      pendingFollowups: pendingResult.rows[0].count,
      recentLeads: recentLeadsResult.rows
    });
  } catch (err) {
    console.error('Mobile dashboard API error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not load dashboard'
    });
  }
});
/* ANDROID WHATSAPP CONVERSATIONS API */
app.get('/api/mobile/whatsapp/conversations', async function(req, res) {
  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const isAdmin = user.role === 'admin';
    const clientId = user.client_id;
    const search = String(req.query.search || '').trim();

    if (
      !isAdmin &&
      (!Number.isSafeInteger(Number(clientId)) || Number(clientId) <= 0)
    ) {
      return res.status(403).json({
        success: false,
        error: 'Valid client account is required'
      });
    }

    const params = [isAdmin ? null : Number(clientId)];

    let query = `
      SELECT
        wm.phone,
        wm.phone_number_id,
        wm.client_id,
        MAX(wm.id) AS last_id,
        MAX(wm.created_at) AS last_time,
        COUNT(*)::int AS message_count,
        COUNT(*) FILTER (
          WHERE wm.direction = 'incoming'
            AND wm.is_read = false
        )::int AS unread_count,
        COALESCE(
          (
            SELECT wc.name
            FROM whatsapp_contacts wc
            WHERE wc.phone = wm.phone
              AND wc.phone_number_id = wm.phone_number_id
              AND wc.client_id IS NOT DISTINCT FROM wm.client_id
            ORDER BY wc.updated_at DESC
            LIMIT 1
          ),
          (
            SELECT c.name
            FROM customers c
            WHERE regexp_replace(COALESCE(c.phone, ''), '[^0-9]', '', 'g')
                = regexp_replace(wm.phone, '[^0-9]', '', 'g')
              AND c.client_id IS NOT DISTINCT FROM wm.client_id
            ORDER BY c.id DESC
            LIMIT 1
          ),
          wm.phone
        ) AS contact_name
      FROM whatsapp_messages wm
      WHERE wm.client_id IS NOT DISTINCT FROM $1::integer
    `;

    if (search) {
      params.push('%' + search + '%');
      query += `
        AND (
          wm.phone ILIKE $${params.length}
          OR EXISTS (
            SELECT 1
            FROM whatsapp_contacts wc
            WHERE wc.phone = wm.phone
              AND wc.phone_number_id = wm.phone_number_id
              AND wc.client_id IS NOT DISTINCT FROM wm.client_id
              AND wc.name ILIKE $${params.length}
          )
        )
      `;
    }

    query += `
      GROUP BY wm.phone, wm.phone_number_id, wm.client_id
      ORDER BY MAX(wm.id) DESC
      LIMIT 200
    `;

    const result = await pool.query(query, params);

    return res.json({
      success: true,
      conversations: result.rows
    });
  } catch (err) {
    console.error('Mobile WhatsApp conversations error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not load WhatsApp conversations'
    });
  }
});
/* ANDROID WHATSAPP DELETE APIs */

app.post('/api/mobile/whatsapp/delete-conversation', async function(req, res) {
  let db;

  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const isAdmin = user.role === 'admin';
    let targetClientId = null;

    if (!isAdmin) {
      const clientId = Number(user.client_id);

      if (!Number.isSafeInteger(clientId) || clientId <= 0) {
        return res.status(403).json({
          success: false,
          error: 'Valid client account is required'
        });
      }

      targetClientId = clientId;
    }

    const phone = String(req.body.phone || '').trim();
    const phoneNumberId =
      String(req.body.phone_number_id || '').trim() || null;

    if (!phone) {
      return res.status(400).json({
        success: false,
        error: 'Phone number is required'
      });
    }

    db = await pool.connect();
    await db.query('BEGIN');

    const result = await db.query(
      `DELETE FROM whatsapp_messages
       WHERE phone = $1
         AND phone_number_id IS NOT DISTINCT FROM $2
         AND client_id IS NOT DISTINCT FROM $3::integer`,
      [phone, phoneNumberId, targetClientId]
    );

    await db.query(
      `DELETE FROM whatsapp_contacts
       WHERE phone = $1
         AND phone_number_id IS NOT DISTINCT FROM $2
         AND client_id IS NOT DISTINCT FROM $3::integer`,
      [phone, phoneNumberId, targetClientId]
    );

    await db.query('COMMIT');

    return res.json({
      success: true,
      deletedMessages: result.rowCount
    });
  } catch (err) {
    if (db) {
      try {
        await db.query('ROLLBACK');
      } catch (rollbackError) {
        console.error('Mobile WhatsApp delete rollback error:', rollbackError);
      }
    }

    console.error('Mobile WhatsApp delete error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not delete conversation'
    });
  } finally {
    if (db) {
      db.release();
    }
  }
});

app.post('/api/mobile/whatsapp/delete-all-conversations', async function(req, res) {
  let db;

  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const isAdmin = user.role === 'admin';
    let targetClientId = null;

    if (!isAdmin) {
      const clientId = Number(user.client_id);

      if (!Number.isSafeInteger(clientId) || clientId <= 0) {
        return res.status(403).json({
          success: false,
          error: 'Valid client account is required'
        });
      }

      targetClientId = clientId;
    }

    db = await pool.connect();
    await db.query('BEGIN');

    const result = await db.query(
      `DELETE FROM whatsapp_messages
       WHERE client_id IS NOT DISTINCT FROM $1::integer`,
      [targetClientId]
    );

    await db.query(
      `DELETE FROM whatsapp_contacts
       WHERE client_id IS NOT DISTINCT FROM $1::integer`,
      [targetClientId]
    );

    await db.query('COMMIT');

    return res.json({
      success: true,
      deletedMessages: result.rowCount
    });
  } catch (err) {
    if (db) {
      try {
        await db.query('ROLLBACK');
      } catch (rollbackError) {
        console.error('Mobile WhatsApp delete-all rollback error:', rollbackError);
      }
    }

    console.error('Mobile WhatsApp delete-all error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not delete conversations'
    });
  } finally {
    if (db) {
      db.release();
    }
  }
});
/* ANDROID WHATSAPP BLOCK USER */

app.post('/api/mobile/whatsapp/block-user', async function(req, res) {
  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const phone = String(req.body.phone || '').trim();
    const requestedPhoneNumberId =
      String(req.body.phone_number_id || '').trim();

    const phoneDigits = phone.replace(/\D/g, '');

    if (
      !/^\d{8,15}$/.test(phoneDigits) ||
      !requestedPhoneNumberId
    ) {
      return res.status(400).json({
        success: false,
        error: 'Valid phone number and WhatsApp number ID are required'
      });
    }

    const isAdmin = user.role === 'admin';
    let token;
    let phoneNumberId;

    if (isAdmin) {
      token = process.env.WHATSAPP_ACCESS_TOKEN;
      phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

      if (phoneNumberId !== requestedPhoneNumberId) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp number does not match this account'
        });
      }
    } else {
      const clientId = Number(user.client_id);

      if (!Number.isSafeInteger(clientId) || clientId <= 0) {
        return res.status(403).json({
          success: false,
          error: 'Valid client account is required'
        });
      }

      const settings = await pool.query(
        `SELECT phone_number_id, access_token
         FROM client_whatsapp_settings
         WHERE client_id = $1
           AND phone_number_id = $2
           AND is_active = TRUE
         LIMIT 1`,
        [clientId, requestedPhoneNumberId]
      );

      if (!settings.rows.length) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp number is not configured for this client'
        });
      }

      phoneNumberId = settings.rows[0].phone_number_id;
      token = settings.rows[0].access_token;
    }

    if (!token || !phoneNumberId) {
      return res.status(500).json({
        success: false,
        error: 'WhatsApp API is not configured'
      });
    }

    const metaResponse = await fetch(
      `https://graph.facebook.com/v23.0/${phoneNumberId}/block_users`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          block_users: [
            {
              user: `+${phoneDigits}`
            }
          ]
        })
      }
    );

    const data = await metaResponse.json();

    if (!metaResponse.ok) {
      return res.status(502).json({
        success: false,
        error: data.error?.message || 'Meta block request failed'
      });
    }

    const blockResult = data.block_users || {};

    if (
      Array.isArray(blockResult.failed_users) &&
      blockResult.failed_users.length > 0
    ) {
      return res.status(502).json({
        success: false,
        error: 'Meta could not block this contact'
      });
    }

    if (
      !Array.isArray(blockResult.added_users) ||
      blockResult.added_users.length === 0
    ) {
      return res.status(502).json({
        success: false,
        error: 'Meta did not confirm the block'
      });
    }

    return res.json({
      success: true,
      message: 'Contact blocked successfully'
    });
  } catch (err) {
    console.error('WhatsApp block user error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not block this contact'
    });
  }
});
/* ANDROID WHATSAPP UNBLOCK API */
app.post('/api/mobile/whatsapp/unblock-user', async function(req, res) {
  try {
    const user = req.session && req.session.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Please login again'
      });
    }

    const phone = String(req.body.phone || '').trim();
    const requestedPhoneNumberId =
      String(req.body.phone_number_id || '').trim();
    const phoneDigits = phone.replace(/\D/g, '');

    if (
      !/^\d{8,15}$/.test(phoneDigits) ||
      !requestedPhoneNumberId
    ) {
      return res.status(400).json({
        success: false,
        error: 'Valid phone number and WhatsApp number ID are required'
      });
    }

    const isAdmin = user.role === 'admin';
    let token;
    let phoneNumberId;

    if (isAdmin) {
      token = process.env.WHATSAPP_ACCESS_TOKEN;
      phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

      if (phoneNumberId !== requestedPhoneNumberId) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp number does not match this account'
        });
      }
    } else {
      const clientId = Number(user.client_id);

      if (!Number.isSafeInteger(clientId) || clientId <= 0) {
        return res.status(403).json({
          success: false,
          error: 'Valid client account is required'
        });
      }

      const settings = await pool.query(
        `SELECT phone_number_id, access_token
         FROM client_whatsapp_settings
         WHERE client_id = $1
           AND phone_number_id = $2
           AND is_active = TRUE
         LIMIT 1`,
        [clientId, requestedPhoneNumberId]
      );

      if (!settings.rows.length) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp number is not configured for this client'
        });
      }

      phoneNumberId = settings.rows[0].phone_number_id;
      token = settings.rows[0].access_token;
    }

    if (!token || !phoneNumberId) {
      return res.status(500).json({
        success: false,
        error: 'WhatsApp API is not configured'
      });
    }

    const metaResponse = await fetch(
      `https://graph.facebook.com/v23.0/${phoneNumberId}/block_users`,
      {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          block_users: [
            {
              user: `+${phoneDigits}`
            }
          ]
        })
      }
    );

    const data = await metaResponse.json();

    if (!metaResponse.ok) {
      console.error('WhatsApp unblock user error:', data);

      return res.status(502).json({
        success: false,
        error: data.error?.message || 'Meta unblock request failed'
      });
    }

    const unblockResult = data.block_users || {};

    if (
      Array.isArray(unblockResult.failed_users) &&
      unblockResult.failed_users.length > 0
    ) {
      return res.status(502).json({
        success: false,
        error: 'Meta could not unblock this contact'
      });
    }

    if (
      !Array.isArray(unblockResult.removed_users) ||
      !unblockResult.removed_users.some(
        item => item.input === `+${phoneDigits}` ||
                item.wa_id === phoneDigits
      )
    ) {
      return res.status(502).json({
        success: false,
        error: 'Meta did not confirm the unblock'
      });
    }

    return res.json({
      success: true,
      message: 'Contact unblocked successfully'
    });
  } catch (err) {
    console.error('WhatsApp unblock user error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not unblock this contact'
    });
  }
});
/* DASHBOARD */
app.get('/', requireLogin, async function(req, res) {
  try {
const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;
    const [
      customersResult,
      leadsResult,
      newResult,
      contactedResult,
      interestedResult,
      followupResult,
      convertedResult,
      lostResult,
      pendingFollowupsResult,
      sourceResult,
      recentLeadsResult,
whatsappMessagesResult
    ] = await Promise.all([
            pool.query(
        isAdmin
          ? 'SELECT COUNT(*)::int AS count FROM customers'
          : 'SELECT COUNT(*)::int AS count FROM customers WHERE client_id=$1',
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? 'SELECT COUNT(*)::int AS count FROM leads'
          : 'SELECT COUNT(*)::int AS count FROM leads WHERE client_id=$1',
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='New'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='New' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='Contacted'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='Contacted' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='Interested'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='Interested' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='Follow-up'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='Follow-up' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='Converted'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='Converted' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? "SELECT COUNT(*)::int AS count FROM leads WHERE status='Lost'"
          : "SELECT COUNT(*)::int AS count FROM leads WHERE status='Lost' AND client_id=$1",
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? `
            SELECT COUNT(*)::int AS count
            FROM leads
            WHERE follow_up IS NOT NULL
            AND follow_up >= CURRENT_DATE
          `
          : `
            SELECT COUNT(*)::int AS count
            FROM leads
            WHERE follow_up IS NOT NULL
            AND follow_up >= CURRENT_DATE
            AND client_id=$1
          `,
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? `
            SELECT COALESCE(source, 'Other') AS source, COUNT(*)::int AS count
            FROM leads
            GROUP BY source
            ORDER BY count DESC
          `
          : `
            SELECT COALESCE(source, 'Other') AS source, COUNT(*)::int AS count
            FROM leads
            WHERE client_id=$1
            GROUP BY source
            ORDER BY count DESC
          `,
        isAdmin ? [] : [clientId]
      ),

      pool.query(
        isAdmin
          ? `
            SELECT id, name, phone, source, status, follow_up, notes
            FROM leads
            ORDER BY id DESC
            LIMIT 8
          `
          : `
            SELECT id, name, phone, source, status, follow_up, notes
            FROM leads
            WHERE client_id=$1
            ORDER BY id DESC
            LIMIT 8
          `,
        isAdmin ? [] : [clientId]
      ),

pool.query(
  isAdmin
    ? `SELECT id, phone, message, direction, created_at
       FROM whatsapp_messages
       ORDER BY id DESC
       LIMIT 10`
    : `SELECT id, phone, message, direction, created_at
       FROM whatsapp_messages
       WHERE client_id = $1
       ORDER BY id DESC
       LIMIT 10`,
  isAdmin ? [] : [clientId]
)
 ]);

    const totalCustomers = customersResult.rows[0].count;
    const totalLeads = leadsResult.rows[0].count;
    const newLeads = newResult.rows[0].count;
    const contacted = contactedResult.rows[0].count;
    const interested = interestedResult.rows[0].count;
    const followups = followupResult.rows[0].count;
    const converted = convertedResult.rows[0].count;
    const lost = lostResult.rows[0].count;
    const pendingFollowups = pendingFollowupsResult.rows[0].count;

    const conversionRate =
      totalLeads > 0
        ? ((converted / totalLeads) * 100).toFixed(1)
        : '0.0';

    const maxSourceCount = Math.max(
      1,
      ...sourceResult.rows.map(row => Number(row.count))
    );

    const sourceBars = sourceResult.rows.map(row => {
      const width = Math.round((Number(row.count) / maxSourceCount) * 100);

      return `
        <div class="source-row">
          <div class="source-top">
            <span>${esc(row.source)}</span>
            <strong>${row.count}</strong>
          </div>
          <div class="source-track">
            <div class="source-fill" style="width:${width}%"></div>
          </div>
        </div>
      `;
    }).join('');
const whatsappMessages = whatsappMessagesResult.rows;
    const recentLeads = recentLeadsResult.rows.map(lead => `
  <tr>
    <td><strong>${esc(lead.name)}</strong></td>

    <td>
      ${esc(lead.phone || '-')}
      ${
        lead.phone
          ? `
            <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">
              <a href="tel:${esc(lead.phone)}" class="badge source" style="text-decoration:none;">
                ðŸ“ž Call
              </a>
              <a href="https://wa.me/${String(lead.phone).replace(/[^0-9]/g, '')}" target="_blank" class="badge status" style="text-decoration:none;">
                ðŸ’¬ WhatsApp
              </a>
            </div>
          `
          : ''
      }
    </td>

    <td>
      <span class="badge source">
        ${esc(lead.source || 'Other')}
      </span>
    </td>

    <td>
      <span class="badge status">
        ${esc(lead.status || '-')}
      </span>
    </td>

    <td>
      ${lead.follow_up ? esc(String(lead.follow_up).slice(0, 10)) : '-'}
    </td>
  </tr>
`).join('');

    const content = `
      <style>
        .dash-head {
          display:flex;
          justify-content:space-between;
          align-items:center;
          gap:20px;
          margin-bottom:24px;
          flex-wrap:wrap;
        }

        .dash-head h1 {
          margin:0;
          font-size:30px;
        }

        .dash-head p {
          margin:7px 0 0;
          color:#94a3b8;
        }

        .dash-actions {
          display:flex;
          gap:10px;
          flex-wrap:wrap;
        }

        .dash-btn {
          display:inline-block;
          padding:11px 16px;
          border-radius:10px;
          text-decoration:none;
          color:white;
          background:#2563eb;
          font-weight:700;
        }

        .dash-btn.secondary {
          background:#334155;
        }

        .kpi-grid {
          display:grid;
          grid-template-columns:repeat(4, 1fr);
          gap:16px;
          margin-bottom:20px;
        }

        .kpi {
          background:#111827;
          border:1px solid #1f2937;
          border-radius:16px;
          padding:20px;
          box-shadow:0 10px 30px rgba(0,0,0,.15);
        }

        .kpi-label {
          color:#94a3b8;
          font-size:14px;
          margin-bottom:10px;
        }

        .kpi-number {
          font-size:30px;
          font-weight:800;
        }

        .kpi-small {
          margin-top:8px;
          color:#64748b;
          font-size:13px;
        }

        .kpi.blue { border-top:4px solid #3b82f6; }
        .kpi.purple { border-top:4px solid #8b5cf6; }
        .kpi.green { border-top:4px solid #22c55e; }
        .kpi.orange { border-top:4px solid #f59e0b; }

        .dash-grid {
          display:grid;
          grid-template-columns:1.5fr 1fr;
          gap:20px;
          margin-bottom:20px;
        }

        .panel {
          background:#111827;
          border:1px solid #1f2937;
          border-radius:16px;
          padding:20px;
          box-shadow:0 10px 30px rgba(0,0,0,.12);
        }

        .panel-title {
          font-size:18px;
          font-weight:800;
          margin-bottom:18px;
        }

        .status-grid {
          display:grid;
          grid-template-columns:repeat(2,1fr);
          gap:12px;
        }

        .status-box {
          padding:16px;
          border-radius:12px;
          background:#0f172a;
          border:1px solid #1e293b;
        }

        .status-box span {
          color:#94a3b8;
          font-size:13px;
        }

        .status-box strong {
          display:block;
          font-size:25px;
          margin-top:6px;
        }

        .source-row {
          margin-bottom:17px;
        }

        .source-top {
          display:flex;
          justify-content:space-between;
          margin-bottom:7px;
          color:#cbd5e1;
        }

        .source-track {
          height:9px;
          background:#1e293b;
          border-radius:99px;
          overflow:hidden;
        }

        .source-fill {
          height:100%;
          background:#3b82f6;
          border-radius:99px;
        }

        .conversion-box {
          text-align:center;
          padding:12px 0 4px;
        }

        .conversion-number {
          font-size:48px;
          font-weight:900;
          color:#22c55e;
        }

        .conversion-text {
          color:#94a3b8;
        }

        .table-wrap {
          overflow-x:auto;
        }

        .dash-table {
          width:100%;
          border-collapse:collapse;
        }

        .dash-table th,
        .dash-table td {
          padding:13px 10px;
          border-bottom:1px solid #1f2937;
          text-align:left;
          white-space:nowrap;
        }

        .dash-table th {
          color:#94a3b8;
          font-size:13px;
        }

        .badge {
          display:inline-block;
          padding:5px 9px;
          border-radius:999px;
          font-size:12px;
          font-weight:700;
          background:#1e293b;
          color:#cbd5e1;
        }

        .badge.source {
          background:#172554;
          color:#93c5fd;
        }

        .badge.status {
          background:#052e16;
          color:#86efac;
        }

        @media(max-width:900px) {
          .kpi-grid {
            grid-template-columns:repeat(2,1fr);
          }

          .dash-grid {
            grid-template-columns:1fr;
          }
        }

        @media(max-width:600px) {
          .kpi-grid {
            grid-template-columns:1fr;
          }

          .dash-head h1 {
            font-size:25px;
          }

          .panel {
            padding:15px;
          }
        }

@media (max-width: 600px) {
  /* Dashboard only: mobile layout */
  body:has(.dash-head) .topbar h1 {
    display: none;
  }

  .dash-head {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 14px;
    margin-bottom: 18px;
  }

  .dash-head h1 {
    margin: 0 0 6px;
    font-size: 25px;
    line-height: 1.25;
  }

  .dash-head p {
    margin: 0;
    font-size: 14px;
    line-height: 1.5;
  }

  .dash-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    width: 100%;
  }

  .dash-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    padding: 10px;
    text-align: center;
    font-size: 14px;
    border-radius: 12px;
  }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }

  .kpi {
    min-width: 0;
    padding: 15px;
    border-radius: 16px;
  }

  .kpi-label {
    font-size: 13px;
    line-height: 1.4;
  }

  .kpi-number {
    font-size: 28px;
    line-height: 1.25;
    margin: 8px 0;
  }

  .kpi-small {
    font-size: 12px;
    line-height: 1.4;
    overflow-wrap: anywhere;
  }

  .dash-grid {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 14px;
  }

  .quick-actions,
  .status-box,
  .today-box,
  .panel {
    min-width: 0;
    padding: 15px;
    border-radius: 16px;
  }

    .action-buttons {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .action-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 0;
    min-height: 44px;
    max-width: 100%;
    padding: 10px;
    text-align: center;
    overflow-wrap: anywhere;
    border-radius: 12px;
    box-sizing: border-box;
  }
    .status-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px 12px;
    min-width: 0;
  }

  .status-item span {
    flex: 1 1 140px;
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .status-item strong {
    flex: 0 0 auto;
    overflow-wrap: anywhere;
  }
  .status-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
}

      </style>

      <div class="dash-head">
        <div>
          <h1>Dashboard</h1>
          <p>Welcome back! Here's what's happening with your CRM.</p>
        </div>

        <div class="dash-actions">
          <a class="dash-btn" href="/leads?add=1">+ Add Lead</a>          <a class="dash-btn secondary" href="/customers?add=1">+ Customer</a>        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi blue">
          <div class="kpi-label">Total Customers</div>
          <div class="kpi-number">${totalCustomers}</div>
          <div class="kpi-small">All customers</div>
        </div>

        <div class="kpi purple">
          <div class="kpi-label">Total Leads</div>
          <div class="kpi-number">${totalLeads}</div>
          <div class="kpi-small">${newLeads} new leads</div>
        </div>

        <div class="kpi green">
          <div class="kpi-label">Converted</div>
          <div class="kpi-number">${converted}</div>
          <div class="kpi-small">${conversionRate}% conversion rate</div>
        </div>

        <div class="kpi orange">
          <div class="kpi-label">Pending Follow-ups</div>
          <div class="kpi-number">${pendingFollowups}</div>
          <div class="kpi-small">Upcoming follow-ups</div>
        </div>
      </div>

      <div class="dash-grid">
<div class="quick-actions">
  <h2>âš¡ Quick Actions</h2>
  <div class="action-buttons">
   <a href="/leads?add=1" class="action-btn">âž• Add Lead</a>   <a href="/customers?add=1" class="action-btn">ðŸ‘¤ Add Customer</a>    <a href="/followups" class="action-btn">ðŸ“… Follow-ups</a>
    <a href="/api-info" class="action-btn">ðŸ”— API Info</a>
  </div>
</div>

<div class="status-box">
  <h2>ðŸ“± WhatsApp & API Status</h2>
  <div class="status-item">
    <span>WhatsApp Business API</span>
    <strong>âšª Not Connected</strong>
  </div>
  <div class="status-item">
    <span>CRM API</span>
    <strong>ðŸŸ¢ Running</strong>
  </div>
</div>
<div class="today-box">
  <h2>ðŸ“Œ Today's Follow-ups</h2>
  <p>Check today's scheduled follow-ups.</p>

  <div class="action-buttons">
    <a href="/followups" class="action-btn">View Follow-ups â†’</a>
    <a href="/leads" class="action-btn">View All Leads â†’</a>
  </div>
</div>
        <div class="panel">
          <div class="panel-title">Lead Status Overview</div>

          <div class="status-grid">
            <div class="status-box">
              <span>New</span>
              <strong>${newLeads}</strong>
            </div>

            <div class="status-box">
              <span>Contacted</span>
              <strong>${contacted}</strong>
            </div>

            <div class="status-box">
              <span>Interested</span>
              <strong>${interested}</strong>
            </div>

            <div class="status-box">
              <span>Follow-up</span>
              <strong>${followups}</strong>
            </div>

            <div class="status-box">
              <span>Converted</span>
              <strong>${converted}</strong>
            </div>

            <div class="status-box">
              <span>Lost</span>
              <strong>${lost}</strong>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-title">Lead Sources</div>
          ${sourceBars || '<p style="color:#94a3b8">No leads yet.</p>'}
        </div>

      </div>

      <div class="dash-grid">

        <div class="panel">
          <div class="panel-title">Conversion Performance</div>

          <div class="conversion-box">
            <div class="conversion-number">${conversionRate}%</div>
            <div class="conversion-text">
              ${converted} converted out of ${totalLeads} total leads
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-title">Follow-up Summary</div>

          <div class="status-grid">
            <div class="status-box">
              <span>Upcoming</span>
              <strong>${pendingFollowups}</strong>
            </div>

            <div class="status-box">
              <span>Follow-up Leads</span>
              <strong>${followups}</strong>
            </div>
          </div>
        </div>

      </div>
<div class="panel">
      <div class="panel">

async function sendWhatsAppMessage(event) {
  event.preventDefault();

  const to = document.getElementById('waPhone').value.trim();
  const message = document.getElementById('waMessage').value.trim();

  if (!to || !message) {
    alert('Phone number and message are required');
    return false;
  }

  try {
    const response = await fetch('/whatsapp/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        to: to,
        message: message
      })
    });

    const data = await response.json();

    if (!response.ok) {
      alert('Message failed: ' + JSON.stringify(data.error));
      return false;
    }

    // Success popup removed
    document.getElementById('waMessage').value = '';
    location.reload();

  } catch (err) {
    alert('Error sending WhatsApp message');
  }

  return false;
}
</script>
      <div class="panel">
        <div class="panel-title">Recent Leads</div>

        <div class="table-wrap">
          <table class="dash-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Phone</th>
                <th>Source</th>
                <th>Status</th>
                <th>Follow-up</th>
              </tr>
            </thead>

            <tbody>
              ${recentLeads || `
                <tr>
                  <td colspan="5" style="color:#94a3b8">
                    No leads found.
                  </td>
                </tr>
              `}
            </tbody>
          </table>
        </div>
      </div>
    `;

 res.send(
  page(
    'Dashboard',
    content,
    'dashboard',
    req.session.user.role,
    req.session.user.role === 'admin'
      ? 'ðŸ’– Vipin_0_6 ðŸ–¤'
      : 'â˜ ï¸ vipin_B2B âš ï¸'
  )
);
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('Dashboard error: ' + err.message);
  }
});


/* REPORTS */

app.get('/reports', requireLogin, async function(req, res) {
  try {
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    if (!isAdmin && !clientId) {
      return res.status(403).send('Access denied');
    }

    const customerResult = await pool.query(
      isAdmin
        ? 'SELECT COUNT(*)::int AS count FROM customers'
        : 'SELECT COUNT(*)::int AS count FROM customers WHERE client_id = $1',
      isAdmin ? [] : [clientId]
    );

    const leadResult = await pool.query(
      isAdmin
        ? 'SELECT COUNT(*)::int AS count FROM leads'
        : 'SELECT COUNT(*)::int AS count FROM leads WHERE client_id = $1',
      isAdmin ? [] : [clientId]
    );

    const convertedResult = await pool.query(
      isAdmin
        ? "SELECT COUNT(*)::int AS count FROM leads WHERE status = 'Converted'"
        : "SELECT COUNT(*)::int AS count FROM leads WHERE status = 'Converted' AND client_id = $1",
      isAdmin ? [] : [clientId]
    );

    const totalCustomers = customerResult.rows[0].count;
    const totalLeads = leadResult.rows[0].count;
    const convertedLeads = convertedResult.rows[0].count;

    const conversionRate = totalLeads > 0
      ? ((convertedLeads / totalLeads) * 100).toFixed(1)
      : '0.0';

    let clientSummary = '';

    if (isAdmin) {
      const summaryResult = await pool.query(`
        SELECT
          c.id,
          c.name,
          COUNT(DISTINCT cu.id)::int AS total_customers,
          COUNT(DISTINCT l.id)::int AS total_leads,
          COUNT(DISTINCT l.id) FILTER (
            WHERE l.status = 'Converted'
          )::int AS converted_leads
        FROM clients c
        LEFT JOIN customers cu ON cu.client_id = c.id
        LEFT JOIN leads l ON l.client_id = c.id
        GROUP BY c.id, c.name
        ORDER BY c.id ASC
      `);

      let summaryRows = '';

      summaryResult.rows.forEach(function(client) {
        const rate = client.total_leads > 0
          ? ((client.converted_leads / client.total_leads) * 100).toFixed(1)
          : '0.0';

        summaryRows += `
          <tr>
            <td>${esc(client.name)}</td>
            <td>${client.total_customers}</td>
            <td>${client.total_leads}</td>
            <td>${client.converted_leads}</td>
            <td>${rate}%</td>
          </tr>
        `;
      });

      if (!summaryRows) {
        summaryRows = '<tr><td colspan="5" class="muted">No clients found.</td></tr>';
      }

      clientSummary = `
        <div class="card">
          <h2>Client-wise Summary</h2>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Client</th>
                  <th>Total Customers</th>
                  <th>Total Leads</th>
                  <th>Converted Leads</th>
                  <th>Conversion Rate</th>
                </tr>
              </thead>
              <tbody>${summaryRows}</tbody>
            </table>
          </div>
        </div>
      `;
    }

    const content = `
      <div class="card">
        <h2>CRM Reports</h2>
        <p>Summary of your CRM data.</p>
      </div>

      <div class="card">
        <h3>Total Customers</h3>
        <p style="font-size:28px;font-weight:bold">${totalCustomers}</p>
      </div>

      <div class="card">
        <h3>Total Leads</h3>
        <p style="font-size:28px;font-weight:bold">${totalLeads}</p>
      </div>

      <div class="card">
        <h3>Converted Leads</h3>
        <p style="font-size:28px;font-weight:bold">${convertedLeads}</p>
      </div>

      <div class="card">
        <h3>Conversion Rate</h3>
        <p style="font-size:28px;font-weight:bold">${conversionRate}%</p>
      </div>

      ${clientSummary}
    `;

    res.send(page('Reports', content, 'reports', req.session.user.role, req.session.user.username));
  } catch (err) {
    console.error('Reports error:', err);
    res.status(500).send('Reports error: ' + esc(err.message));
  }
});


/* CUSTOMERS */
app.post('/customers/add', requireLogin, async function(req, res) {

  try {

    const name = String(req.body.name || '').trim();
    const phone = String(req.body.phone || '').trim();
    const email = String(req.body.email || '').trim();
    const address = String(req.body.address || '').trim();

    if (!name) {
      return res.status(400).send('Customer name required');
    }

    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    if (isAdmin) {

      await pool.query(
        `INSERT INTO customers
         (name, phone, email, address)
         VALUES($1,$2,$3,$4)`,
        [
          name,
          phone,
          email,
          address
        ]
      );

    } else {

      await pool.query(
        `INSERT INTO customers
         (client_id, name, phone, email, address)
         VALUES($1,$2,$3,$4,$5)`,
        [
          clientId,
          name,
          phone,
          email,
          address
        ]
      );

    }

    res.redirect('/customers');

  } catch (err) {

    console.error('Customer add error:', err);
    res.status(500).send(
      'Customer add error: ' + err.message
    );

  }

});
app.post('/customers/edit/:id', requireLogin, async function(req, res) {

  try {

    const customerId = Number(req.params.id);
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;
if (!isAdmin && !clientId) {
  return res.status(403).send('Access denied');
}
   if (isAdmin) {

      await pool.query(
        `UPDATE customers
         SET name=$1,
             phone=$2,
             email=$3,
             address=$4
         WHERE id=$5`,
        [
          req.body.name || '',
          req.body.phone || '',
          req.body.email || '',
          req.body.address || '',
          customerId
        ]
      );

    } else {

      await pool.query(
        `UPDATE customers
         SET name=$1,
             phone=$2,
             email=$3,
             address=$4
         WHERE id=$5
         AND client_id=$6`,
        [
          req.body.name || '',
          req.body.phone || '',
          req.body.email || '',
          req.body.address || '',
          customerId,
          clientId
        ]
      );

    }

    res.redirect('/customers');

  } catch (err) {

    console.error('Customer edit error:', err);
    res.status(500).send('Customer edit error: ' + err.message);

  }

});
app.post('/customers/delete/:id', requireLogin, async function(req, res) {

  try {

    const customerId = Number(req.params.id);
if (!Number.isSafeInteger(customerId) || customerId <= 0) {
  return res.status(400).send('Invalid customer ID');
}
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;
if (!isAdmin && !clientId) {
  return res.status(403).send('Access denied');
}
    if (isAdmin) {

      await pool.query(
        `DELETE FROM customers
         WHERE id=$1`,
        [
          customerId
        ]
      );

    } else {

      await pool.query(
        `DELETE FROM customers
         WHERE id=$1
         AND client_id=$2`,
        [
          customerId,
          clientId
        ]
      );

    }

    res.redirect('/customers');

  } catch (err) {

    console.error('Customer delete error:', err);
    res.status(500).send('Customer delete error: ' + err.message);

  }

});

app.get('/customers', requireLogin, async function(req, res) {

  try {

    const search = String(req.query.search || '').trim();

    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;
     if (search) {

      if (isAdmin) {

        result = await pool.query(
          `SELECT *
           FROM customers
           WHERE name ILIKE $1
           OR phone ILIKE $1
           OR email ILIKE $1
           ORDER BY created_at DESC`,
          ['%' + search + '%']
        );

      } else {

        result = await pool.query(
          `SELECT *
           FROM customers
           WHERE client_id=$1
           AND (
             name ILIKE $2
             OR phone ILIKE $2
             OR email ILIKE $2
           )
           ORDER BY created_at DESC`,
          [
            clientId,
            '%' + search + '%'
          ]
        );
      }

    } else {

      if (isAdmin) {

        result = await pool.query(
          `SELECT *
           FROM customers
           ORDER BY created_at DESC`
        );

      } else {

        result = await pool.query(
          `SELECT *
           FROM customers
           WHERE client_id=$1
           ORDER BY created_at DESC`,
          [clientId]
        );
      }
    }

    const editId = req.query.edit
      ? Number(req.query.edit)
      : null;

    let editCustomer = null;

    if (editId) {

      let editResult;

      if (isAdmin) {

        editResult = await pool.query(
          'SELECT * FROM customers WHERE id=$1',
          [editId]
        );

      } else {

        editResult = await pool.query(
          `SELECT *
           FROM customers
           WHERE id=$1
           AND client_id=$2`,
          [
            editId,
            clientId
          ]
        );
      }

      editCustomer = editResult.rows[0] || null;
    }

    let rows = '';

    result.rows.forEach(function(customer) {

      rows += `
      <tr>
        <td>${esc(customer.name)}</td>
        <td>${esc(customer.phone)}</td>
        <td>${esc(customer.email)}</td>
        <td>${esc(customer.address)}</td>
        <td>
          <div class="actions">

            <a class="btn btn-gray"
               href="/customers?edit=${customer.id}">
              Edit
            </a>

            <form method="POST"
                  action="/customers/delete/${customer.id}"
                  onsubmit="return confirm('Delete this customer?')">

              <button class="btn btn-danger" type="submit">
                Delete
              </button>

            </form>

          </div>
        </td>
      </tr>
      `;
    });

    if (!rows) {
      rows =
        '<tr><td colspan="5" class="muted">No customers found.</td></tr>';
    }

    let form = '';

    if (editCustomer) {

      form = `
      <div class="card">
      <h2>Edit Customer</h2>

      <form method="POST"
            action="/customers/edit/${editCustomer.id}">

      <div class="form-grid">

      <div class="form-group">
      <label>Name</label>
      <input name="name" required value="${esc(editCustomer.name)}">
      </div>

      <div class="form-group">
      <label>Phone</label>
      <input name="phone" value="${esc(editCustomer.phone)}">
      </div>

      <div class="form-group">
      <label>Email</label>
      <input name="email" type="email" value="${esc(editCustomer.email)}">
      </div>

      <div class="form-group">
      <label>Address</label>
      <input name="address" value="${esc(editCustomer.address)}">
      </div>

      </div>

      <button class="btn" type="submit">
        Update Customer
      </button>

      <a class="btn btn-gray" href="/customers">
        Cancel
      </a>

      </form>
      </div>
      `;

    } else if (req.query.add) {

      form = `
      <div class="card">
      <h2>Add Customer</h2>

      <form method="POST" action="/customers/add">

      <div class="form-grid">

      <div class="form-group">
      <label>Name</label>
      <input name="name" required>
      </div>

      <div class="form-group">
      <label>Phone</label>
      <input name="phone">
      </div>

      <div class="form-group">
      <label>Email</label>
      <input name="email" type="email">
      </div>

      <div class="form-group">
      <label>Address</label>
      <input name="address">
      </div>

      </div>

      <button class="btn" type="submit">
        Save Customer
      </button>

      </form>
      </div>
      `;
    }

    const content = `

<div class="card">

<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">

<form method="GET"
      action="/customers"
      style="display:flex;gap:8px;flex:1">

<input
name="search"
placeholder="Search name, phone or email..."
value="${esc(search)}">

<button class="btn" type="submit">
Search
</button>

</form>

<a class="btn" href="/customers?add=1">
+ Add Customer
</a>

</div>

</div>

${form}

<div class="card">

<h2>Customers</h2>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>Name</th>
<th>Phone</th>
<th>Email</th>
<th>Address</th>
<th>Actions</th>
</tr>
</thead>

<tbody>
${rows}
</tbody>

</table>

</div>
</div>
`;

   res.send(
  page(
    'Customers',
    content,
    'customers',
    req.session.user.role
  )
);
  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Customers error: ' + esc(err.message)
    );
  }

});
/* LEADS */

app.get('/leads', requireLogin, async function(req, res) {

  try {

    const search = String(req.query.search || '').trim();
    const status = String(req.query.status || '').trim();
    const source = String(req.query.source || '').trim();

  const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;

let conditions = [];
let params = [];

if (!isAdmin) {

  params.push(clientId);

  conditions.push(
    `client_id=$${params.length}`
  );

}

    if (search) {

      params.push('%' + search + '%');

      conditions.push(
        `(name ILIKE $${params.length}
          OR phone ILIKE $${params.length}
          OR email ILIKE $${params.length})`
      );
    }

    if (status) {

      params.push(status);

      conditions.push(
        `status=$${params.length}`
      );
    }

    if (source) {

      params.push(source);

      conditions.push(
        `source=$${params.length}`
      );
    }

    let query = `
      SELECT *
      FROM leads
    `;

    if (conditions.length) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);

    const editId = req.query.edit
      ? Number(req.query.edit)
      : null;

    let editLead = null;

    if (editId) {

      let editResult;

if (isAdmin) {

  editResult = await pool.query(
    'SELECT * FROM leads WHERE id=$1',
    [editId]
  );

} else {

  editResult = await pool.query(
    'SELECT * FROM leads WHERE id=$1 AND client_id=$2',
    [editId, clientId]
  );

}
      editLead = editResult.rows[0] || null;
    }

    let rows = '';

    result.rows.forEach(function(lead) {

      const date = lead.follow_up
        ? new Date(lead.follow_up).toISOString().slice(0,10)
        : '-';

      rows += `
      <tr>

      <td>
        <strong>${esc(lead.name)}</strong>
        <br>
        <span class="muted">${esc(lead.email)}</span>
      </td>

      <td>${esc(lead.phone)}</td>

      <td>
        <span class="badge">
          ${esc(lead.source || 'Other')}
        </span>
      </td>

      <td>
        <span class="badge">
          ${esc(lead.status || 'New')}
        </span>
      </td>

      <td>${esc(date)}</td>

      <td>

      <div class="actions">

      <a class="btn btn-gray"
         href="/leads?edit=${lead.id}">
         Edit
      </a>

      <form method="POST"
            action="/leads/delete/${lead.id}"
            onsubmit="return confirm('Delete this lead?')">

        <button class="btn btn-danger" type="submit">
          Delete
        </button>

      </form>

      </div>

      </td>

      </tr>
      `;
    });

    if (!rows) {
      rows =
        '<tr><td colspan="6" class="muted">No leads found.</td></tr>';
    }

    let form = '';

    if (editLead) {

      let sourceHtml = '';

      sourceOptions.forEach(function(option) {

        sourceHtml += `
        <option value="${esc(option)}"
        ${selected(editLead.source, option)}>
        ${esc(option)}
        </option>
        `;
      });

      let statusHtml = '';

      statusOptions.forEach(function(option) {

        statusHtml += `
        <option value="${esc(option)}"
        ${selected(editLead.status, option)}>
        ${esc(option)}
        </option>
        `;
      });

      const followDate = editLead.follow_up
        ? new Date(editLead.follow_up).toISOString().slice(0,10)
        : '';

      form = `
      <div class="card">

      <h2>Edit Lead</h2>

      <form method="POST"
            action="/leads/edit/${editLead.id}">

      <div class="form-grid">

      <div class="form-group">
      <label>Name</label>
      <input name="name"
             required
             value="${esc(editLead.name)}">
      </div>

      <div class="form-group">
      <label>Phone</label>
      <input name="phone"
             value="${esc(editLead.phone)}">
      </div>

      <div class="form-group">
      <label>Email</label>
      <input name="email"
             type="email"
             value="${esc(editLead.email)}">
      </div>

      <div class="form-group">
      <label>Source</label>
      <select name="source">
      ${sourceHtml}
      </select>
      </div>

      <div class="form-group">
      <label>Status</label>
      <select name="status">
      ${statusHtml}
      </select>
      </div>

      <div class="form-group">
      <label>Follow-up Date</label>
      <input name="follow_up"
             type="date"
             value="${esc(followDate)}">
      </div>

      </div>

      <div class="form-group">
      <label>Notes</label>
      <textarea name="notes">${esc(editLead.notes)}</textarea>
      </div>

      <button class="btn" type="submit">
      Update Lead
      </button>

      <a class="btn btn-gray"
         href="/leads">
      Cancel
      </a>

      </form>

      </div>
      `;

    } else if (req.query.add) {

      let sourceHtml = '';

      sourceOptions.forEach(function(option) {

        sourceHtml += `
        <option value="${esc(option)}">
        ${esc(option)}
        </option>
        `;
      });

      let statusHtml = '';

      statusOptions.forEach(function(option) {

        statusHtml += `
        <option value="${esc(option)}">
        ${esc(option)}
        </option>
        `;
      });

      form = `
      <div class="card">

      <h2>Add Lead</h2>

      <form method="POST"
            action="/leads/add">

      <div class="form-grid">

      <div class="form-group">
      <label>Name</label>
      <input name="name" required>
      </div>

      <div class="form-group">
      <label>Phone</label>
      <input name="phone">
      </div>

      <div class="form-group">
      <label>Email</label>
      <input name="email" type="email">
      </div>

      <div class="form-group">
      <label>Source</label>
      <select name="source">
      ${sourceHtml}
      </select>
      </div>

      <div class="form-group">
      <label>Status</label>
      <select name="status">
      ${statusHtml}
      </select>
      </div>

      <div class="form-group">
      <label>Follow-up Date</label>
      <input name="follow_up" type="date">
      </div>

      </div>

      <div class="form-group">
      <label>Notes</label>
      <textarea name="notes"></textarea>
      </div>

      <button class="btn" type="submit">
      Save Lead
      </button>

      </form>

      </div>
      `;
    }

    let sourceFilter = '';

    sourceOptions.forEach(function(option) {

      sourceFilter += `
      <option value="${esc(option)}"
      ${selected(source, option)}>
      ${esc(option)}
      </option>
      `;
    });

    let statusFilter = '';

    statusOptions.forEach(function(option) {

      statusFilter += `
      <option value="${esc(option)}"
      ${selected(status, option)}>
      ${esc(option)}
      </option>
      `;
    });

    const content = `

<div class="card">

<form method="GET"
      action="/leads">

<div class="search-row">

<input name="search"
       placeholder="Search lead..."
       value="${esc(search)}">

<select name="status">
<option value="">All Status</option>
${statusFilter}
</select>

<select name="source">
<option value="">All Sources</option>
${sourceFilter}
</select>

<button class="btn" type="submit">
Filter
</button>

</div>

</form>

<a class="btn" href="/leads?add=1">
+ Add Lead
</a>

</div>

${form}

<div class="card">

<h2>Leads</h2>

<div class="table-wrap">

<table>

<thead>

<tr>
<th>Lead</th>
<th>Phone</th>
<th>Source</th>
<th>Status</th>
<th>Follow-up</th>
<th>Actions</th>
</tr>

</thead>

<tbody>
${rows}
</tbody>

</table>

</div>

</div>
`;

    res.send(
  page(
    'Leads',
    content,
    'leads',
    req.session.user.role
  )
);

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Leads error: ' + esc(err.message)
    );
  }

});

app.post('/leads/add', requireLogin, async function(req, res) {

  try {

    const name = String(req.body.name || '').trim();

    if (!name) {
      return res.redirect('/leads?add=1');
    }

   const clientId = req.session.user.client_id;

await pool.query(
  `INSERT INTO leads
   (client_id,name,phone,email,source,status,follow_up,notes)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [
    clientId,
    name,
    req.body.phone || '',
    req.body.email || '',
    req.body.source || 'Other',
    req.body.status || 'New',
    req.body.follow_up || null,
    req.body.notes || ''
  ]
);
    res.redirect('/leads');

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Add lead error: ' + esc(err.message)
    );
  }

});

app.post('/leads/edit/:id', requireLogin, async function(req, res) {

  try {

   const leadId = Number(req.params.id);

if (!Number.isSafeInteger(leadId) || leadId <= 0) {
  return res.status(400).send('Invalid lead ID');
}
const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;
if (!isAdmin && !clientId) {
  return res.status(403).send('Access denied');
}

let result;
if (isAdmin) {

  result = await pool.query(
    `UPDATE leads
     SET name=$1,
         phone=$2,
         email=$3,
         source=$4,
         status=$5,
         follow_up=$6,
         notes=$7
     WHERE id=$8`,
    [
      req.body.name || '',
      req.body.phone || '',
      req.body.email || '',
      req.body.source || 'Other',
      req.body.status || 'New',
      req.body.follow_up || null,
      req.body.notes || '',
      leadId
    ]
  );

} else {

  result = await pool.query(
      `UPDATE leads
     SET name=$1,
         phone=$2,
         email=$3,
         source=$4,
         status=$5,
         follow_up=$6,
         notes=$7
     WHERE id=$8
     AND client_id=$9`,
    [
      req.body.name || '',
      req.body.phone || '',
      req.body.email || '',
      req.body.source || 'Other',
      req.body.status || 'New',
      req.body.follow_up || null,
      req.body.notes || '',
      leadId,
      clientId
    ]
  );

}
if (result.rowCount === 0) {
  return res.status(404).send('Lead not found or access denied');
}
    res.redirect('/leads');

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Edit lead error: ' + esc(err.message)
    );
  }

});

app.post('/leads/delete/:id', requireLogin, async function(req, res) {

  try {

    const leadId = Number(req.params.id);

    if (!Number.isSafeInteger(leadId) || leadId <= 0) {
      return res.status(400).send('Invalid lead ID');
    }

    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    let result;

    if (isAdmin) {

      result = await pool.query(
        'DELETE FROM leads WHERE id=$1',
        [leadId]
      );

    } else {

      if (!clientId) {
        return res.status(403).send('Access denied');
      }

      result = await pool.query(
        'DELETE FROM leads WHERE id=$1 AND client_id=$2',
        [leadId, clientId]
      );

    }

    if (result.rowCount === 0) {
      return res.status(404).send('Lead not found or access denied');
    }

    res.redirect('/leads');

  } catch (err) {

    console.error('Delete lead error:', err);

    res.status(500).send('Could not delete lead');

  }

});


/* FOLLOW UPS */

// Mark a follow-up as completed
app.post('/followups/:id/complete', requireLogin, async function(req, res) {
  try {
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;
    const leadId = Number(req.params.id);

    if (!Number.isInteger(leadId) || leadId <= 0) {
      return res.status(400).send('Invalid lead ID');
    }

    let result;

    if (isAdmin) {
      result = await pool.query(
        `UPDATE leads
         SET follow_up_completed = TRUE
         WHERE id = $1 AND follow_up IS NOT NULL`,
        [leadId]
      );
    } else {
      result = await pool.query(
        `UPDATE leads
         SET follow_up_completed = TRUE
         WHERE id = $1
           AND client_id = $2
           AND follow_up IS NOT NULL`,
        [leadId, clientId]
      );
    }

    if (result.rowCount === 0) {
      return res.status(404).send('Follow-up not found');
    }

    res.redirect('/followups?filter=completed');
  } catch (err) {
    console.error(err);
    res.status(500).send('Could not complete follow-up');
  }
});


app.get('/followups', requireLogin, async function(req, res) {
  try {
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;
    const filter = ['today', 'pending', 'overdue', 'completed', 'all']
      .includes(req.query.filter) ? req.query.filter : 'all';

    const conditions = ['follow_up IS NOT NULL'];
    const params = [];

    if (!isAdmin) {
      params.push(clientId);
      conditions.push(`client_id = $${params.length}`);
    }

    if (filter === 'completed') {
      conditions.push('follow_up_completed = TRUE');
    } else {
      conditions.push('COALESCE(follow_up_completed, FALSE) = FALSE');

      if (filter !== 'all') {
        conditions.push(`status NOT IN ('Converted', 'Lost')`);
      }

      if (filter === 'today') {
        conditions.push('follow_up = CURRENT_DATE');
      } else if (filter === 'pending') {
        conditions.push('follow_up > CURRENT_DATE');
      } else if (filter === 'overdue') {
        conditions.push('follow_up < CURRENT_DATE');
      }
    }

    const result = await pool.query(
      `SELECT *
       FROM leads
       WHERE ${conditions.join(' AND ')}
       ORDER BY follow_up ASC`,
      params
    );

    let rows = '';

    result.rows.forEach(function(lead) {
      const date = String(lead.follow_up).slice(0, 10);
      const isCompleted = lead.follow_up_completed === true;

      rows += `
        <tr>
          <td>${esc(lead.name)}</td>
          <td>${esc(lead.phone || '')}</td>
          <td>${esc(lead.status || '')}</td>
          <td>
            <span class="badge">${esc(date)}</span>
            ${!isCompleted && date < new Date().toISOString().slice(0, 10)
              ? '<span class="badge">Overdue</span>'
              : ''}
          </td>
          <td>
            <a class="btn btn-gray" href="/leads?edit=${lead.id}">Open</a>
            ${
              isCompleted
                ? '<span class="badge">Completed</span>'
                : `<form method="POST" action="/followups/${lead.id}/complete" style="display:inline">
                     <button class="btn" type="submit">Mark Complete</button>
                   </form>`
            }
          </td>
        </tr>
      `;
    });

    if (!rows) {
      rows = '<tr><td colspan="5" class="muted">No follow-ups found for this filter.</td></tr>';
    }

    const filters = [
      ['all', 'All'],
      ['today', 'Today'],
      ['pending', 'Pending'],
      ['overdue', 'Overdue'],
      ['completed', 'Completed']
    ];

    const filterLinks = filters.map(function(item) {
      const active = filter === item[0] ? 'btn' : 'btn btn-gray';
      return `<a class="${active}" href="/followups?filter=${item[0]}">${item[1]}</a>`;
    }).join(' ');

    const content = `
      <div class="card">
        <h2>Follow-up Management</h2>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
          ${filterLinks}
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Lead</th>
                <th>Phone</th>
                <th>Status</th>
                <th>Follow-up</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
    `;

    res.send(
      page('Follow-ups', content, 'followups', req.session.user.role)
    );
  } catch (err) {
    console.error(err);
    res.status(500).send('Follow-ups error: ' + esc(err.message));
  }
});


/* STAFF */

app.get('/staff', requireAdmin, async function(req, res) {

  try {

    const result = await pool.query(`
      SELECT id,username,role,created_at
      FROM users
      ORDER BY id ASC
    `);

    let rows = '';

    result.rows.forEach(function(user) {

     rows += `
  <tr>
    <td>${esc(user.username)}</td>
    <td><span class="badge">${esc(user.role)}</span></td>
    <td>${new Date(user.created_at).toISOString().slice(0,10)}</td>
    <td>
      <form method="POST" action="/staff/reset-password/${user.id}" style="display:flex;gap:8px;">
        <input name="password" type="password" placeholder="New password" required>
        <button class="btn" type="submit">Reset</button>
      </form>
    </td>
  </tr>
`;
});
    const content = `

<div class="grid-2">

<div class="card">

<h2>Add Staff</h2>

<form method="POST" action="/staff/add">

<div class="form-group">
<label>Username</label>
<input name="username" required>
</div>

<div class="form-group">
<label>Password</label>
<input name="password" type="password" required>
</div>

<div class="form-group">
<label>Role</label>

<select name="role">
<option value="staff">Staff</option>
<option value="admin">Admin</option>
</select>

</div>

<button class="btn" type="submit">
Add Staff
</button>

</form>

</div>

<div class="card">

<h2>Users</h2>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>Username</th>
<th>Role</th>
<th>Created</th>
</tr>
</thead>

<tbody>
${rows}
</tbody>

</table>

</div>

</div>

</div>
`;

    res.send(
      page(
        'Staff',
        content,
        'staff',
        req.session.user.username
      )
    );

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Staff error: ' + esc(err.message)
    );
  }

});

app.post('/staff/add', requireAdmin, async function(req, res) {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) {
      return res.status(400).send('Username and password required');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users(username, password, role)
       VALUES($1, $2, $3)`,
      [
        username,
        hashedPassword,
        req.body.role === 'admin' ? 'admin' : 'staff'
      ]
    );

    res.redirect('/staff');
  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Add staff error: ' + esc(err.message)
    );
  }
});
app.post('/staff/reset-password/:id', requireAdmin, async function(req, res) {
  try {
    const userId = Number(req.params.id);
    const newPassword = String(req.body.password || '');

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).send('Invalid user ID');
    }

    if (!newPassword) {
      return res.status(400).send('Password required');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    const result = await pool.query(
      `UPDATE users
       SET password = $1
       WHERE id = $2`,
      [hashedPassword, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('User not found');
    }

    res.redirect('/staff');
  } catch (err) {
    console.error(err);
    res.status(500).send(
      'Reset password error: ' + esc(err.message)
    );
  }
});

/* =========================
   CLIENT MANAGEMENT
========================= */

app.get('/clients', requireAdmin, async function(req, res) {
  try {
        const result = await pool.query(
      "SELECT id, name, email, phone, status, api_key, created_at FROM clients ORDER BY id DESC"
    );
    let rows = '';

    result.rows.forEach(function(client) {
      rows += `
        <tr>
          <td>${client.id}</td>
          <td>${esc(client.name)}</td>
          <td>${esc(client.email || '')}</td>
          <td>${esc(client.phone || '')}</td>
         <td>${esc(client.status || 'active')}</td>

         <td>
           <code>${esc(client.api_key || '')}</code>
         </td>

         <td>
<a href="/clients/${client.id}/edit">Edit Client</a>
<a href="/clients/${client.id}/auto-reply">Edit Website / Auto Reply</a>
  <form method="POST" action="/clients/${client.id}/status" style="display:inline;">
    <input type="hidden" name="status" value="${
      client.status === 'active' ? 'inactive' : 'active'
    }">
    <button type="submit">
      ${client.status === 'active' ? 'Deactivate' : 'Activate'}
    </button>
  </form>
</td>
        </tr>
      `;
    });

    const content = `
      <div class="card">
        <h2>Add Client</h2>

       <form method="POST" action="/clients">
  <input
    type="text"
    name="name"
    placeholder="Client name"
    required
  >

  <input
    type="email"
    name="email"
    placeholder="Email"
  >

  <input
    type="text"
    name="phone"
    placeholder="Phone"
  >

  <input
    type="text"
    name="username"
    placeholder="Client username"
    required
  >

  <input
    type="password"
    name="password"
    placeholder="Client password"
    required
  >

  <button type="submit">Add Client</button>
</form>
      </div>

      <div class="card">
        <h2>Clients</h2>

        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Phone</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            ${rows || `
              <tr>
                <td colspan="6">No clients found</td>
              </tr>
            `}
          </tbody>
        </table>
      </div>
    `;

    res.send(
      page(
        'Clients',
        content,
        'clients',
        req.session.user.username
      )
    );

  } catch (err) {
    console.error('Clients page error:', err);

    res.status(500).send(
      page(
        'Clients',
        '<div class="card"><h2>Error</h2><p>Unable to load clients.</p></div>',
        'clients',
        req.session.user.username
      )
    );
  }
});


app.post('/clients', requireAdmin, async function(req, res) {
  const db = await pool.connect();

  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim();
    const phone = String(req.body.phone || '').trim();
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!name) {
      return res.status(400).send('Client name required');
    }

    if (!username || !password.trim()) {
      return res.status(400).send('Username and password required');
    }

    if (username.length > 100) {
      return res.status(400).send('Username must be 100 characters or less');
    }

    if (password.length < 8) {
      return res.status(400).send('Password must be at least 8 characters');
    }

    const apiKey = crypto.randomBytes(32).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 12);

    await db.query('BEGIN');

    const clientResult = await db.query(
      `INSERT INTO clients(name, email, phone, status, api_key)
       VALUES($1, $2, $3, 'active', $4)
       RETURNING id`,
      [name, email, phone, apiKey]
    );

    const clientId = clientResult.rows[0].id;

    await db.query(
      `INSERT INTO users(username, password, role, client_id)
       VALUES($1, $2, 'client', $3)`,
      [username, hashedPassword, clientId]
    );

    await db.query('COMMIT');
    return res.redirect('/clients');

  } catch (err) {
    await db.query('ROLLBACK').catch(() => {});

    console.error('Add client error:', err);

    if (err.code === '23505') {
      return res.status(400).send('Username already exists. Please choose another username.');
    }

    return res.status(500).send('Unable to add client. Please try again.');

  } finally {
    db.release();
  }
});
app.post('/clients/:id/status', requireAdmin, async function(req, res) {
  try {
    const status =
      req.body.status === 'inactive'
        ? 'inactive'
        : 'active';

    await pool.query(
      `
      UPDATE clients
      SET status=$1
      WHERE id=$2
      `,
      [
        status,
        Number(req.params.id)
      ]
    );

    res.redirect('/clients');

  } catch (err) {
    console.error('Client status update error:', err);
    res.status(500).send('Unable to update client status');
  }
});

app.get('/clients/:id/edit', requireAdmin, async function(req, res) {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).send('Invalid client ID');
    }

    const result = await pool.query(
      'SELECT id, name, email, phone, website_url, whatsapp_auto_reply_message FROM clients WHERE id=$1',
      [id]
    );

    if (!result.rows[0]) {
      return res.status(404).send('Client not found');
    }

    const client = result.rows[0];

    const content = `
      <div class="card">
        <h2>Edit Client</h2>

        <form method="POST" action="/clients/${client.id}/edit">
          <label>Client Name</label>
          <input name="name" value="${esc(client.name)}" required>

          <label>Email</label>
          <input type="email" name="email" value="${esc(client.email || '')}">

          <label>Phone</label>
          <input name="phone" value="${esc(client.phone || '')}">
          <label>Website URL</label>
          <input
            type="url"
            name="website_url"
            value="${esc(client.website_url || '')}"
            placeholder="https://example.com"
          >

          <label>WhatsApp Automatic Reply Message</label>
          <textarea
            name="whatsapp_auto_reply_message"
            rows="4"
            placeholder="Customer ko bheja jane wala automatic reply"
          >${esc(client.whatsapp_auto_reply_message || '')}</textarea>
<label>WhatsApp Phone Number ID</label>
<input
  name="wa_phone_number_id"
  placeholder="WhatsApp Phone Number ID"
>

<label>WhatsApp Business Phone</label>
<input
  name="wa_display_phone"
  placeholder="WhatsApp Business Phone"
>

<label>WhatsApp Access Token</label>
<input
  type="password"
  name="wa_access_token"
  placeholder="WhatsApp Access Token"
>
          <button type="submit">Save Changes</button>
          <a href="/clients">Cancel</a>
        </form>
      </div>
    `;

    res.send(
      page('Edit Client', content, 'clients', req.session.user.username)
    );

  } catch (err) {
    console.error('Client edit page error:', err);
    res.status(500).send('Unable to load client edit page');
  }
});

app.get('/clients/:id/auto-reply', requireAdmin, async function(req, res) {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).send('Invalid client ID');
    }

    const result = await pool.query(
      `SELECT id, name, website_url, whatsapp_auto_reply_message
       FROM clients
       WHERE id = $1`,
      [id]
    );

    if (!result.rows[0]) {
      return res.status(404).send('Client not found');
    }

    const client = result.rows[0];

    const content = `
      <div class="card">
        <h2>Website / WhatsApp Auto Reply</h2>
        <p>Client: ${esc(client.name)}</p>

        <form method="POST" action="/clients/${client.id}/auto-reply">
          <label>Website URL</label>
          <input
            type="url"
            name="website_url"
            value="${esc(client.website_url || '')}"
            placeholder="https://example.com"
          >

          <label>WhatsApp Automatic Reply Message</label>
          <textarea
            name="whatsapp_auto_reply_message"
            rows="5"
            placeholder="Customer ko bheja jane wala automatic reply"
          >${esc(client.whatsapp_auto_reply_message || '')}</textarea>

          <button type="submit">Save Website / Auto Reply</button>
          <a href="/clients">Cancel</a>
        </form>
      </div>
    `;

    res.send(page(
      'Website / Auto Reply',
      content,
      'clients',
      req.session.user.username
    ));
  } catch (err) {
    console.error('Client auto-reply page error:', err);
    res.status(500).send('Unable to load Website / Auto Reply page');
  }
});

app.post('/clients/:id/auto-reply', requireAdmin, async function(req, res) {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).send('Invalid client ID');
    }

    const websiteUrl = String(req.body.website_url || '').trim();
    const autoReplyMessage = String(
      req.body.whatsapp_auto_reply_message || ''
    ).trim();

    const result = await pool.query(
      `UPDATE clients
       SET website_url = $1,
           whatsapp_auto_reply_message = $2
       WHERE id = $3
       RETURNING id`,
      [websiteUrl || null, autoReplyMessage || null, id]
    );

    if (!result.rows[0]) {
      return res.status(404).send('Client not found');
    }

    res.redirect(`/clients/${id}/auto-reply`);
  } catch (err) {
    console.error('Client auto-reply save error:', err);
    res.status(500).send('Unable to save Website / Auto Reply settings');
  }
});

app.post('/clients/:id/edit', requireAdmin, async function(req, res) {
  const db = await pool.connect();

  try {
    const id = Number(req.params.id);
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim();
    const phone = String(req.body.phone || '').trim();

    const waPhoneNumberId = String(
      req.body.wa_phone_number_id || ''
    ).trim();

    const waDisplayPhone = String(
      req.body.wa_display_phone || ''
    ).trim();

    const waAccessToken = String(
      req.body.wa_access_token || ''
    ).trim();

    if (!Number.isInteger(id) || id <= 0 || !name) {
      return res.status(400).send(
        'Valid client ID and name are required'
      );
    }

    await db.query('BEGIN');

        const websiteUrl = String(
      req.body.website_url || ''
    ).trim();

    const autoReplyMessage = String(
      req.body.whatsapp_auto_reply_message || ''
    ).trim();

    const result = await db.query(
      `UPDATE clients
       SET name = $1,
           email = $2,
           phone = $3,
           website_url = $4,
           whatsapp_auto_reply_message = $5
       WHERE id = $6
       RETURNING id`,
      [
        name,
        email || null,
        phone || null,
        websiteUrl || null,
        autoReplyMessage || null,
        id
      ]
    );
    if (!result.rows[0]) {
      await db.query('ROLLBACK');
      return res.status(404).send('Client not found');
    }

    // Read existing WhatsApp settings.
    const existingResult = await db.query(
      `SELECT phone_number_id, display_phone_number, access_token
       FROM client_whatsapp_settings
       WHERE client_id = $1`,
      [id]
    );

    const existing = existingResult.rows[0];

    // Leave WhatsApp settings untouched if all fields are blank.
    const waFieldsProvided =
      waPhoneNumberId !== '' ||
      waDisplayPhone !== '' ||
      waAccessToken !== '';

    if (waFieldsProvided) {
      const finalPhoneNumberId =
        waPhoneNumberId || (existing?.phone_number_id || '');

      const finalAccessToken =
        waAccessToken || (existing?.access_token || '');

      const finalDisplayPhone =
        waDisplayPhone ||
        (existing?.display_phone_number || '');

      if (!finalPhoneNumberId || !finalAccessToken) {
        await db.query('ROLLBACK');
        return res.status(400).send(
          'WhatsApp Phone Number ID and Access Token are required for first-time setup.'
        );
      }
      const duplicatePhoneResult = await db.query(
        `SELECT client_id
         FROM client_whatsapp_settings
         WHERE phone_number_id = $1
           AND client_id <> $2
           AND is_active = TRUE
         LIMIT 1`,
        [finalPhoneNumberId, id]
      );

      if (duplicatePhoneResult.rows.length > 0) {
        await db.query('ROLLBACK');
        return res.status(409).send(
          'This WhatsApp Phone Number ID is already assigned to another active client.'
        );
      }
      await db.query(
        `INSERT INTO client_whatsapp_settings
          (client_id, phone_number_id, display_phone_number,
           access_token, is_active, updated_at)
         VALUES ($1, $2, $3, $4, TRUE, NOW())
         ON CONFLICT (client_id)
         DO UPDATE SET
           phone_number_id = EXCLUDED.phone_number_id,
           display_phone_number = EXCLUDED.display_phone_number,
           access_token = EXCLUDED.access_token,
           is_active = TRUE,
           updated_at = NOW()`,
        [
          id,
          finalPhoneNumberId,
          finalDisplayPhone || null,
          finalAccessToken
        ]
      );
    }

    await db.query('COMMIT');
    res.redirect('/clients');

  } catch (err) {
    await db.query('ROLLBACK').catch(() => {});
    console.error('Client edit save error:', err);
    res.status(500).send(
      'Unable to save client changes'
    );
  } finally {
    db.release();
  }
});
/* API INFO */

app.get('/api-info', requireLogin, function(req, res) {

  const content = `

<div class="card">

<h2>CRM API</h2>

<p class="muted">
These endpoints can later be connected with website,
ads, WhatsApp Business API and other systems.
</p>

<h3>Health</h3>

<pre>/health</pre>

<h3>Customers</h3>

<pre>GET /api/customers</pre>

<h3>Leads</h3>

<pre>GET /api/leads</pre>

<pre>POST /api/leads</pre>

<h3>Example Lead JSON</h3>

<pre>{
  "name": "Rahul",
  "phone": "9876543210",
  "email": "rahul@example.com",
  "source": "WhatsApp",
  "status": "New",
  "follow_up": "2026-10-01",
  "notes": "Interested in product"
}</pre>

</div>
`;

  res.send(
    page(
      'API',
      content,
      'api',
      req.session.user.username
    )
  );

});
/* WHATSAPP WEBHOOK */

app.get('/webhook/whatsapp', function(req, res) {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  const verifyToken = process.env.WHATSAPP_VERIFY_TOKEN;

  if (!verifyToken) {
    console.error('WHATSAPP_VERIFY_TOKEN is not configured');
    return res.sendStatus(503);
  }
  if (mode === 'subscribe' && token === verifyToken) {
    return res.status(200).send(challenge);
  }

  res.sendStatus(403);
});
app.post('/webhook/whatsapp', async function(req, res) {

  try {
     const appSecret = process.env.WHATSAPP_APP_SECRET;
    const signature = req.get('X-Hub-Signature-256');

    if (!appSecret) {
      console.error('WHATSAPP_APP_SECRET is not configured');
      return res.sendStatus(503);
    }

    if (
      !req.rawBody ||
      !signature ||
      !/^sha256=[a-f0-9]{64}$/i.test(signature)
    ) {
      return res.sendStatus(401);
    }

    const expectedSignature =
      'sha256=' +
      crypto
        .createHmac('sha256', appSecret)
        .update(req.rawBody)
        .digest('hex');

    const receivedBuffer = Buffer.from(signature, 'utf8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

    if (
      receivedBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
    ) {
      console.warn('WhatsApp webhook signature verification failed');
      return res.sendStatus(401);
    }

    console.log('WhatsApp webhook received');

    const value = req.body?.entry?.[0]?.changes?.[0]?.value;

    if (!value) {
      return res.sendStatus(200);
    }

    const messages = value.messages || [];
const phoneNumberId = value.metadata?.phone_number_id || '';
console.log('Incoming webhook Phone Number ID:', phoneNumberId);
if (!phoneNumberId) {
  console.warn('Webhook missing phone_number_id');
  return res.sendStatus(200);
}

    // Identify which client owns this WhatsApp number.
    const settingsResult = await pool.query(
      `SELECT client_id
       FROM client_whatsapp_settings
       WHERE phone_number_id = $1
         AND is_active = TRUE
       LIMIT 1`,
      [phoneNumberId]
    );

    let clientId = null;

    if (settingsResult.rows.length > 0) {
      clientId = settingsResult.rows[0].client_id;
    } else if (
      phoneNumberId !== process.env.WHATSAPP_PHONE_NUMBER_ID
    ) {
      // Do not assign an unknown number's messages to another client.
      console.warn('No client configured for WhatsApp number:', phoneNumberId);
      return res.sendStatus(200);
    }

    // Update delivery statuses only after identifying the number owner.
    const statuses = value.statuses || [];

    for (const status of statuses) {
      const whatsappMessageId = status.id || '';
      const deliveryStatus = status.status || '';

      if (!whatsappMessageId || !deliveryStatus) continue;

      const errorDetails = Array.isArray(status.errors)
        ? JSON.stringify(status.errors)
        : null;

      await pool.query(
        `UPDATE whatsapp_messages
         SET delivery_status = $1,
             delivery_error = $2,
             status_updated_at = NOW()
         WHERE whatsapp_message_id = $3
           AND phone_number_id = $4
           AND client_id IS NOT DISTINCT FROM $5::integer`,
        [
          deliveryStatus,
          errorDetails,
          whatsappMessageId,
          phoneNumberId,
          clientId
        ]
      );

      console.log('WhatsApp delivery status updated', {
        whatsappMessageId,
        deliveryStatus
      });
    }
    for (const msg of messages) {

      const phone = msg.from || '';
      const whatsappMessageId = msg.id || '';
      const contact = (value.contacts || []).find(
        c => String(c.wa_id || '') === String(msg.from || '')
      );

      const contactName = String(
  contact?.profile?.name || ''
).trim();

console.log('WhatsApp contact profile:', {
  phone,
  contactName,
  hasContact: Boolean(contact)
});
      if (phoneNumberId && phone && contactName) {
  if (clientId === null) {
    await pool.query(
      `INSERT INTO whatsapp_contacts
        (client_id, phone_number_id, phone, name, updated_at)
       VALUES (NULL, $1, $2, $3, NOW())
       ON CONFLICT (phone_number_id, phone)
       WHERE client_id IS NULL
       DO UPDATE SET
         name = EXCLUDED.name,
         updated_at = NOW()`,
      [phoneNumberId, phone, contactName]
    );
  } else {
    await pool.query(
      `INSERT INTO whatsapp_contacts
        (client_id, phone_number_id, phone, name, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (client_id, phone_number_id, phone)
       DO UPDATE SET
         name = EXCLUDED.name,
         updated_at = NOW()`,
      [clientId, phoneNumberId, phone, contactName]
    );
  }
}
      if (!phone) continue;

           let message = '';
      let mediaId = null;
      let mediaMimeType = null;
      let mediaType = null;

      if (msg.type === 'text') {
        message = msg.text?.body || '';
      } else if (
        ['audio', 'image', 'video', 'document', 'sticker'].includes(msg.type)
      ) {
        const media = msg[msg.type];
        mediaId = media?.id || null;
        mediaMimeType = media?.mime_type || null;
        mediaType = msg.type;
        message = `[${msg.type} message]`;
      } else {
        message = `[${msg.type || 'unknown'} message]`;
      }

           const insertResult = await pool.query(
        `INSERT INTO whatsapp_messages
          (client_id, phone_number_id, phone, message,
           direction, whatsapp_message_id, media_type,
           media_id, media_mime_type)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
WHERE TRUE
        ON CONFLICT (client_id, phone_number_id, whatsapp_message_id)
  WHERE direction = 'incoming'
    AND whatsapp_message_id IS NOT NULL
  DO NOTHING
RETURNING id`,
        [
          clientId,
          phoneNumberId,
          phone,
          message,
          'incoming',
          whatsappMessageId || null,
          mediaType,
          mediaId,
          mediaMimeType
        ]
      );

      if (insertResult.rows.length === 0) {
        console.log('Duplicate WhatsApp message skipped', {
          clientId,
          phone,
          whatsappMessageId
        });
        continue;
      }

      await sendIncomingWhatsAppPush(clientId, phone, message);
      // Automatically create leads only for Click-to-WhatsApp ad referrals.
      const referral = msg.referral || null;

      if (
        referral &&
        String(referral.source_type || '').toLowerCase() === 'ad'
      ) {
        const existingLead = await pool.query(
          `SELECT id
           FROM leads
           WHERE phone = $1
             AND client_id IS NOT DISTINCT FROM $2::integer
           LIMIT 1`,
          [phone, clientId]
        );

        if (existingLead.rows.length === 0) {
          const referralNotes = `WhatsApp ad referral: ${JSON.stringify({
            source_type: referral.source_type || null,
            source_id: referral.source_id || null,
            headline: referral.headline || null,
            body: referral.body || null,
            source_url: referral.source_url || null,
            ctwa_clid: referral.ctwa_clid || null
          })}`;

          await pool.query(
            `INSERT INTO leads
             (client_id, name, phone, email, source, status, notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
              clientId,
              contactName || phone,
              phone,
              '',
              'WhatsApp',
              'New',
              referralNotes
            ]
          );

          console.log('Automatic WhatsApp ad lead created', {
            clientId,
            phone,
            sourceType: referral.source_type
          });
        }
      }

      // Send the automatic reply only once per customer,
      // for this client and WhatsApp business number.
      if (clientId !== null && clientId !== undefined) {
        try {
          const autoReplyResult = await pool.query(
            `SELECT c.website_url,
                    c.whatsapp_auto_reply_message,
                    w.access_token,
                    w.phone_number_id
             FROM clients c
             JOIN client_whatsapp_settings w
               ON w.client_id = c.id
             WHERE c.id = $1
               AND w.phone_number_id = $2
               AND w.is_active = TRUE
             LIMIT 1`,
            [clientId, phoneNumberId]
          );

          const autoReplySettings = autoReplyResult.rows[0];

          if (
            autoReplySettings &&
            autoReplySettings.access_token &&
            autoReplySettings.phone_number_id &&
            autoReplySettings.whatsapp_auto_reply_message
          ) {
            const replyParts = [
              autoReplySettings.whatsapp_auto_reply_message.trim(),
              autoReplySettings.website_url
                ? `Website: ${autoReplySettings.website_url.trim()}`
                : ''
            ].filter(Boolean);

            const autoReplyText = replyParts.join('\n\n');

            if (autoReplyText) {
              const reservationResult = await pool.query(
                `INSERT INTO whatsapp_auto_reply_sent
                   (client_id, phone_number_id, phone)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (client_id, phone_number_id, phone)
                 DO NOTHING
                 RETURNING id`,
                [
                  clientId,
                  autoReplySettings.phone_number_id,
                  phone
                ]
              );

              if (reservationResult.rows.length > 0) {
                let autoReplyResponse;
                let autoReplyData;

                try {
                  autoReplyResponse = await fetch(
                    `https://graph.facebook.com/v23.0/${autoReplySettings.phone_number_id}/messages`,
                    {
                      method: 'POST',
                      headers: {
                        Authorization:
                          `Bearer ${autoReplySettings.access_token}`,
                        'Content-Type': 'application/json'
                      },
                      body: JSON.stringify({
                        messaging_product: 'whatsapp',
                        to: phone,
                        type: 'text',
                        text: { body: autoReplyText }
                      })
                    }
                  );

                  autoReplyData = await autoReplyResponse.json();

                  if (!autoReplyResponse.ok) {
                    throw new Error(
                      JSON.stringify(autoReplyData.error || autoReplyData)
                    );
                  }
                } catch (sendError) {
                  await pool.query(
                    `DELETE FROM whatsapp_auto_reply_sent
                     WHERE client_id = $1
                       AND phone_number_id = $2
                       AND phone = $3`,
                    [
                      clientId,
                      autoReplySettings.phone_number_id,
                      phone
                    ]
                  );

                  throw sendError;
                }

                await pool.query(
                  `INSERT INTO whatsapp_messages
                   (client_id, phone_number_id, phone, message,
                    direction, whatsapp_message_id, delivery_status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                  [
                    clientId,
                    autoReplySettings.phone_number_id,
                    phone,
                    autoReplyText,
                    'outgoing',
                    autoReplyData.messages?.[0]?.id || null,
                    'accepted'
                  ]
                );

                console.log('WhatsApp first auto-reply accepted', {
                  clientId,
                  phone
                });
              } else {
                console.log('WhatsApp auto-reply already sent; skipped', {
                  clientId,
                  phone
                });
              }
            }
          }
        } catch (autoReplyError) {
          console.error('WhatsApp auto-reply failed:', autoReplyError);
        }
      }

                           console.log('Incoming WhatsApp message saved', {
        clientId,
        phone,
        whatsappMessageId
      });
    }
    res.sendStatus(200);

  } catch (err) {
    console.error('WhatsApp webhook error:', err);
    res.sendStatus(500);
  }
});
/* WHATSAPP SEND MESSAGE */
/* =========================
   WHATSAPP CHAT INBOX
========================= */
/* =========================
   DELETE WHATSAPP CONVERSATION
========================= */
app.post('/whatsapp/delete-conversation', requireLogin, async function(req, res) {
  let db;

  try {
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    const phone = String(req.body.phone || '').trim();
    const phoneNumberId =
      String(req.body.phone_number_id || '').trim() || null;

    if (!phone) {
      return res.status(400).send('Phone number is required.');
    }

    if (!isAdmin && !clientId) {
      return res.status(403).send('Access denied.');
    }

   let targetClientId;

if (isAdmin) {
  const postedClientId = String(req.body.client_id || '').trim();

  // Admin may delete only global WhatsApp conversations.
  if (postedClientId !== '') {
    return res.status(403).send(
      'Admin cannot delete client WhatsApp conversations.'
    );
  }

  targetClientId = null;
} else {
  // Client session decides ownership; never trust the form's client_id.
  targetClientId = Number(clientId);

  if (!Number.isSafeInteger(targetClientId) || targetClientId <= 0) {
    return res.status(403).send('Valid client account is required.');
  }
}
    db = await pool.connect();

    await db.query('BEGIN');

    // Remove only messages belonging to this exact conversation.
    const deleteMessages = await db.query(
      `DELETE FROM whatsapp_messages
       WHERE phone = $1
         AND phone_number_id IS NOT DISTINCT FROM $2
         AND client_id IS NOT DISTINCT FROM $3::integer`,
      [phone, phoneNumberId, targetClientId]
    );

    // Remove the saved contact name for this same conversation.
    await db.query(
      `DELETE FROM whatsapp_contacts
       WHERE phone = $1
         AND phone_number_id IS NOT DISTINCT FROM $2
         AND client_id IS NOT DISTINCT FROM $3::integer`,
      [phone, phoneNumberId, targetClientId]
    );

    await db.query('COMMIT');

    console.log(
      'WhatsApp conversation deleted:',
      phone,
      'client:',
      targetClientId,
      'messages:',
      deleteMessages.rowCount
    );

    return res.redirect('/whatsapp');

  } catch (err) {
    if (db) {
      try {
        await db.query('ROLLBACK');
      } catch (rollbackError) {
        console.error('WhatsApp delete rollback error:', rollbackError);
      }
    }

    console.error('WhatsApp conversation delete error:', err);
    return res.status(500).send('Conversation delete failed. Check server logs.');
  } finally {
    if (db) {
      db.release();
    }
  }
});
app.get('/whatsapp', requireLogin, async function(req, res) {
  try {
    const search = String(req.query.search || '').trim();
    const selectedPhone = String(req.query.phone || '').trim();
const selectedPhoneNumberId = String(req.query.phone_number_id || '').trim();
const selectedConversationClientId = String(req.query.client_id || '').trim();
    const isAdmin = req.session.user.role === 'admin';
   const clientId = req.session.user.client_id;

if (
  !isAdmin &&
  (!Number.isSafeInteger(Number(clientId)) || Number(clientId) <= 0)
) {
  return res.status(403).send('Valid client account is required');
}
if (!isAdmin && !clientId) {
  return res.status(403).send('Access denied');
}
    // Mark messages as read only within the current account's inbox.
    if (selectedPhone) {
      const readQuery = `
        UPDATE whatsapp_messages
        SET is_read = true
        WHERE phone = $1
          AND phone_number_id IS NOT DISTINCT FROM $2
          AND direction = 'incoming'
          AND client_id IS NOT DISTINCT FROM $3::integer
      `;

      await pool.query(readQuery, [
        selectedPhone,
        selectedPhoneNumberId || null,
        isAdmin ? null : clientId
      ]);
    }

    // Build conversations visible to this account only.
    let conversationsQuery = `
      SELECT
        wm.phone,
        wm.phone_number_id,
        wm.client_id,
        MAX(wm.id) AS last_id,
        MAX(wm.created_at) AS last_time,
        COUNT(*)::int AS message_count,
        COUNT(*) FILTER (
          WHERE wm.direction = 'incoming'
            AND wm.is_read = false
        )::int AS unread_count,
        COALESCE(
          (
            SELECT wc.name
            FROM whatsapp_contacts wc
            WHERE wc.phone = wm.phone
              AND wc.phone_number_id = wm.phone_number_id
              AND wc.client_id IS NOT DISTINCT FROM wm.client_id
            ORDER BY wc.updated_at DESC
            LIMIT 1
          ),
          (
            SELECT c.name
            FROM customers c
            WHERE regexp_replace(COALESCE(c.phone, ''), '[^0-9]', '', 'g')
                = regexp_replace(wm.phone, '[^0-9]', '', 'g')
              AND c.client_id IS NOT DISTINCT FROM wm.client_id
            ORDER BY c.id DESC
            LIMIT 1
          ),
          wm.phone
        ) AS contact_name
      FROM whatsapp_messages wm
      WHERE wm.client_id IS NOT DISTINCT FROM $1::integer
    `;

    const params = [isAdmin ? null : clientId];

    if (search) {
      params.push('%' + search + '%');
      conversationsQuery += ` AND wm.phone ILIKE $${params.length}`;
    }

    conversationsQuery += `
      GROUP BY wm.phone, wm.phone_number_id, wm.client_id
      ORDER BY last_id DESC
    `;

    const conversationsResult = await pool.query(
      conversationsQuery,
      params
    );

    // Admin sees global chats only; clients see their own chats only.
    const showConversationList = req.query.view === 'chats';

    let phone = '';
    let phoneNumberId = '';
    let conversationClientId = null;
    let selectedChat = null;

    if (!showConversationList) {
      selectedChat = conversationsResult.rows.find(chat => {
        return (
          chat.phone === selectedPhone &&
          chat.phone_number_id === selectedPhoneNumberId &&
          (
            isAdmin
              ? chat.client_id == null
              : Number(chat.client_id) === Number(clientId)
          )
        );
      });

      if (!selectedChat && conversationsResult.rows.length > 0) {
        selectedChat = conversationsResult.rows[0];
      }

      if (selectedChat) {
        phone = selectedChat.phone;
        phoneNumberId = selectedChat.phone_number_id;
        conversationClientId = selectedChat.client_id;
      }
    }

    // Load messages only for the selected account-owned conversation.
    let messages = [];

    if (phone) {
      const messageQuery = `
        SELECT
          id,
          phone,
          message,
          direction,
          created_at,
          media_type,
          media_id,
          media_mime_type,
          delivery_status
        FROM whatsapp_messages
        WHERE phone = $1
          AND phone_number_id IS NOT DISTINCT FROM $2
          AND client_id IS NOT DISTINCT FROM $3::integer
        ORDER BY id ASC
      `;

      const messageResult = await pool.query(messageQuery, [
        phone,
        phoneNumberId || null,
        isAdmin ? null : clientId
      ]);

      messages = messageResult.rows;
    }

    // Conversation list HTML
    const conversationRows =
  conversationsResult.rows.map(chat => {

    const active =
      chat.phone === phone
        ? 'background:#1d2945;'
        : '';

    return `
      <div style="
        border-bottom:1px solid #26304a;
        ${active}
      ">

        <a
         href="/whatsapp?phone=${encodeURIComponent(chat.phone)}&phone_number_id=${encodeURIComponent(chat.phone_number_id || '')}&client_id=${chat.client_id == null ? 'global' : encodeURIComponent(String(chat.client_id))}"
          style="
            display:block;
            padding:14px 14px 8px;
            text-decoration:none;
            color:white;
          "
        >

          <div style="
            display:flex;
            justify-content:space-between;
            gap:8px;
          ">

            <strong>
              ${esc(chat.contact_name || chat.phone)}
            </strong>

            ${
              Number(chat.unread_count) > 0
                ? `
                  <span style="
                    background:#22c55e;
                    color:#052e16;
                    padding:3px 8px;
                    border-radius:20px;
                    font-size:11px;
                    font-weight:800;
                  ">
                    ${chat.unread_count}
                  </span>
                `
                : ''
            }

          </div>

          <div style="
            color:#94a3b8;
            font-size:12px;
            margin-top:5px;
          ">
            ${chat.message_count} messages
          </div>

        </a>

        <form
          method="POST"
          action="/whatsapp/delete-conversation"
          onsubmit="return confirm('Kya is conversation ke saved CRM messages delete karne hain?')"
          style="padding:0 14px 12px;"
        >

          <input
            type="hidden"
            name="phone"
            value="${esc(chat.phone)}"
          >

          <input
            type="hidden"
            name="phone_number_id"
            value="${esc(chat.phone_number_id || '')}"
          >

          <input
            type="hidden"
            name="client_id"
            value="${chat.client_id == null ? '' : esc(String(chat.client_id))}"
          >

          <button
            type="submit"
            style="
              background:#991b1b;
              color:white;
              border:1px solid #ef4444;
              border-radius:7px;
              padding:6px 10px;
              cursor:pointer;
              font-size:12px;
            "
          >
            Delete conversation
          </button>

        </form>

      </div>
    `;

  }).join('');

    // Message bubbles

    const messageRows =
      messages.map(msg => {

        const incoming =
          msg.direction === 'incoming';

        const mediaUrl = msg.media_id
          ? '/whatsapp/media/' + encodeURIComponent(msg.media_id)
          : '';

        let mediaContent = '';

        if (mediaUrl && msg.media_type === 'image') {
          mediaContent = `
            <img
              src="${mediaUrl}"
              alt="WhatsApp photo"
              style="display:block;max-width:100%;max-height:300px;border-radius:8px;margin-bottom:8px;"
              loading="lazy"
            >
          `;
        } else if (mediaUrl && msg.media_type === 'audio') {
          mediaContent = `
            <audio
              controls
              preload="none"
              style="display:block;max-width:100%;margin-bottom:8px;"
            >
              <source
                src="${mediaUrl}"
                type="${esc(msg.media_mime_type || 'audio/mpeg')}"
              >
              Your browser does not support audio playback.
            </audio>
          `;
        }

        return `
          <div style="
            display:flex;
            justify-content:${incoming ? 'flex-start' : 'flex-end'};
            margin-bottom:10px;
          ">
            <div style="
              max-width:75%;
              padding:11px 14px;
              border-radius:14px;
              background:${incoming ? '#1e293b' : '#166534'};
              color:white;
            ">
              ${mediaContent}

              <div style="
                font-size:14px;
                line-height:1.45;
                white-space:pre-wrap;
              ">${esc(msg.message || '')}</div>

                            <div style="
                font-size:10px;
                color:#cbd5e1;
                margin-top:5px;
                text-align:right;
              ">
                ${esc(new Date(msg.created_at).toLocaleString('en-IN', {
                  timeZone: 'Asia/Kolkata',
                  day: '2-digit',
                  month: 'short',
                  year: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                  hour12: true
                }))}
              </div>

              ${
                !incoming
                  ? `
                    <div class="wa-delivery-status" style="
                      font-size:11px;
                      color:#bbf7d0;
                      margin-top:3px;
                      text-align:right;
                    ">
                                            ${
                        msg.delivery_status === 'read'
  ? 'Seen'
  : msg.delivery_status === 'delivered'
  ? 'Delivered'
  : msg.delivery_status === 'sent'
  ? 'Sent'
  : msg.delivery_status === 'failed'
  ? 'Failed'
  : 'Sent'                      }
                    </div>
                  `
                  : ''
              }
            </div>
          </div>
        `;

      }).join('');

    const content = `
      <style>

        .wa-layout {
          display:grid;
          grid-template-columns:320px 1fr;
          gap:18px;
          min-height:650px;
        }

        .wa-list {
          background:#111827;
          border:1px solid #26304a;
          border-radius:16px;
          overflow:hidden;
        }

        .wa-chat {
          background:#111827;
          border:1px solid #26304a;
          border-radius:16px;
          display:flex;
          flex-direction:column;
          overflow:hidden;
        }

        .wa-header {
          padding:16px;
          border-bottom:1px solid #26304a;
          font-weight:800;
        }

        .wa-messages {
          flex:1;
          padding:18px;
          overflow-y:auto;
          min-height:450px;
          max-height:560px;
        }

        .wa-compose {
          padding:15px;
          border-top:1px solid #26304a;
        }

        .wa-compose form {
          display:flex;
          gap:8px;
        }

        .wa-compose input {
          flex:1;
        }

        @media(max-width:800px) {

          .wa-layout {
            grid-template-columns:1fr;
          }

          .wa-list {
            max-height:300px;
            overflow-y:auto;
          }

          .wa-messages {
            min-height:400px;
          }

        }
        /* WhatsApp mobile app-style layout */
        @media (max-width: 600px) {
          .wa-layout {
            display: flex;
            flex-direction: column;
            gap: 14px;
            min-height: 0;
          }

          .wa-list,
          .wa-chat {
            width: 100%;
            min-width: 0;
            border-radius: 18px;
            border: 1px solid #263550;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.16);
          }

          .wa-list {
            max-height: 235px;
            overflow-y: auto;
          }

          .wa-header {
            position: sticky;
            top: 0;
            z-index: 2;
            padding: 15px;
            background: #111a2d;
            font-size: 16px;
            overflow-wrap: anywhere;
          }

          .wa-messages {
            min-height: 320px;
            max-height: 52vh;
            padding: 14px 10px;
            overflow-y: auto;
            overscroll-behavior: contain;
          }

          .wa-messages > div > div {
            max-width: 88% !important;
            overflow-wrap: anywhere;
            word-break: break-word;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
          }

          .wa-messages img {
            height: auto;
            object-fit: contain;
          }

          .wa-messages audio {
            max-width: 100%;
          }

          .wa-compose {
            position: sticky;
            bottom: 0;
            z-index: 3;
            padding: 12px;
            background: #111827;
            border-top: 1px solid #2a3852;
          }

          .wa-compose form {
            display: flex;
            flex-direction: column;
            gap: 10px;
          }

          .wa-compose input[type="text"],
          .wa-compose input:not([type]),
          .wa-compose input[type="file"] {
            width: 100%;
            min-width: 0;
            font-size: 16px;
          }

          .wa-compose input[type="file"] {
            padding: 10px;
            font-size: 13px;
          }

          .wa-compose form > div {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
          }

          .wa-compose button {
            min-height: 42px;
            padding: 10px 13px;
            border-radius: 12px;
          }

          .wa-compose button[type="submit"] {
            flex: 1;
          }

                             .wa-compose #waRecordingPreview {
            max-width: 100%;
          }
          .wa-back {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-right: 10px;
            padding: 8px 11px;
            border-radius: 10px;
            background: #075e54;
            color: #ffffff;
            text-decoration: none;
            font-size: 14px;
            font-weight: 700;
            white-space: nowrap;
          }

          .wa-back:hover {
            background: #128c7e;
            color: #ffffff;
          }

          /* WhatsApp mobile full-screen conversation */
          .wa-layout.wa-chat-open .wa-list {
            display: none;
          }

          .wa-layout:not(.wa-chat-open) .wa-chat {
            display: none;
          }

          .wa-layout.wa-chat-open .wa-chat {
            min-height: calc(100dvh - 100px);
            height: calc(100dvh - 100px);
          }

          .wa-layout.wa-chat-open .wa-messages {
            flex: 1;
            min-height: 0;
            max-height: none;
          }
      </style>

<div class="wa-layout ${phone ? 'wa-chat-open' : ''}">
        <!-- LEFT CONVERSATION LIST -->

        <div class="wa-list">

          <div style="
            padding:16px;
            border-bottom:1px solid #26304a;
          ">

            <form
              method="GET"
              action="/whatsapp"
            >

              <input
                name="search"
                placeholder="Search phone..."
                value="${esc(search)}"
              >

            </form>

          </div>

          ${
            conversationRows ||
            `
              <div style="
                padding:20px;
                color:#94a3b8;
              ">
                No WhatsApp conversations yet.
              </div>
            `
          }

        </div>


        <!-- RIGHT CHAT -->

        <div class="wa-chat">

         <div class="wa-header">
  ${
    phone
      ? `<a class="wa-back" href="/whatsapp?view=chats" aria-label="Back to conversations">Chats</a> <span>WhatsApp - ${esc(phone)}</span>`
      : 'WhatsApp Inbox'
  }
</div>

          <!-- MESSAGES -->

          <div class="wa-messages" id="waMessages">

            ${
              messageRows ||
              `
                <div style="
                  color:#94a3b8;
                  text-align:center;
                  padding:80px 20px;
                ">

                  ${
                    phone
                      ? 'No messages yet.'
                      : 'Select a conversation.'
                  }

                </div>
              `
            }

          </div>


          ${
            phone
              ? `


<!-- REPLY BOX -->

<div class="wa-compose">

  <form
    onsubmit="return sendWhatsAppMessage(event)"
    enctype="multipart/form-data"
  >

    <input
      id="waMessage"
      placeholder="Type a message or audio caption..."
      autocomplete="off"
    >

    <input
      id="waMediaFile"
      type="file"
      accept="image/jpeg,image/png,audio/aac,audio/mp4,audio/mpeg,audio/amr,audio/ogg"
    >

    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:8px;">

      <button
        class="btn"
        id="waRecordBtn"
        type="button"
        onclick="startWhatsAppRecording()"
      >
        Record Audio
      </button>

      <button
        class="btn"
        id="waStopRecordBtn"
        type="button"
        onclick="stopWhatsAppRecording()"
        disabled
      >
        â¹ï¸ Stop
      </button>

      <button
        class="btn"
        type="submit"
      >
        Send
      </button>

    </div>

    <div
      id="waRecordingStatus"
      style="font-size:13px; margin-top:8px;"
    ></div>

    <audio
      id="waRecordingPreview"
      controls
      style="display:none; width:100%; margin-top:8px;"
    ></audio>

  </form>

</div>
                </div>


                <script>
const waSelectedPhone = ${JSON.stringify(phone)};
const waSelectedPhoneNumberId = ${JSON.stringify(phoneNumberId)};
const waSelectedClientId = ${JSON.stringify(
  conversationClientId == null
    ? 'global'
    : String(conversationClientId)
)};
let waLastMessageId = ${messages.length ? Number(messages[messages.length - 1].id) : 0};
let waPollingInProgress = false;

async function pollWhatsAppUpdates() {
  const container = document.getElementById('waMessages');

  if (!container || !waSelectedPhone || waPollingInProgress) {
    return;
  }

  waPollingInProgress = true;

  try {
   const response = await fetch(
  '/whatsapp/updates?phone=' +
  encodeURIComponent(waSelectedPhone) +
  '&phone_number_id=' +
  encodeURIComponent(waSelectedPhoneNumberId) +
  '&client_id=' +
  encodeURIComponent(waSelectedClientId) +
  '&after=' + waLastMessageId
);
    if (!response.ok) return;

    const data = await response.json();

    if (!data.success || !Array.isArray(data.messages)) {
      return;
    }
    const statusLabels = {
      read: 'Seen',
      delivered: 'Delivered',
      sent: 'Sent',
      failed: 'Failed',
      accepted: 'Sent'
    };

    for (const status of (data.statuses || [])) {
      const messageRow = container.querySelector(
        '[data-message-id="' + Number(status.id) + '"]'
      );

      const label = messageRow
        ? messageRow.querySelector('.wa-delivery-status')
        : null;

      if (label) {
        label.textContent =
          statusLabels[status.delivery_status] || 'Sent';
      }
    }

    for (const msg of data.messages) {
      const id = Number(msg.id);

      if (!Number.isSafeInteger(id) || id <= waLastMessageId) {
        continue;
      }

      const emptyMessage = container.querySelector(
        'div[style*="text-align:center"]'
      );

      if (emptyMessage) {
        emptyMessage.remove();
      }

      const incoming = msg.direction === 'incoming';

      const row = document.createElement('div');
row.dataset.messageId = String(id);
      row.style.display = 'flex';
      row.style.justifyContent = incoming ? 'flex-start' : 'flex-end';
      row.style.marginBottom = '10px';

      const bubble = document.createElement('div');
      bubble.style.maxWidth = '75%';
      bubble.style.padding = '11px 14px';
      bubble.style.borderRadius = '14px';
      bubble.style.background = incoming ? '#1e293b' : '#166534';
      bubble.style.color = 'white';

      const text = document.createElement('div');
      text.style.fontSize = '14px';
      text.style.lineHeight = '1.45';
      text.style.whiteSpace = 'pre-wrap';
      text.textContent = msg.message || '-';

      const time = document.createElement('div');
      time.style.fontSize = '10px';
      time.style.color = '#cbd5e1';
      time.style.marginTop = '5px';
      time.style.textAlign = 'right';

      time.textContent = new Date(msg.created_at).toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      });


      const mediaUrl = msg.media_id
        ? '/whatsapp/media/' + encodeURIComponent(msg.media_id)
        : '';

      if (mediaUrl && msg.media_type === 'image') {
        const image = document.createElement('img');
        image.src = mediaUrl;
        image.alt = 'WhatsApp photo';
        image.loading = 'lazy';
        image.style.display = 'block';
        image.style.maxWidth = '100%';
        image.style.maxHeight = '300px';
        image.style.borderRadius = '8px';
        image.style.marginBottom = '8px';
        bubble.appendChild(image);
      } else if (mediaUrl && msg.media_type === 'audio') {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.preload = 'none';
        audio.style.display = 'block';
        audio.style.maxWidth = '100%';
        audio.style.marginBottom = '8px';

        const source = document.createElement('source');
        source.src = mediaUrl;
        source.type = msg.media_mime_type || 'audio/mpeg';

        audio.appendChild(source);
        bubble.appendChild(audio);
      }

      if (msg.message) {
        bubble.appendChild(text);
      }

            if (!incoming) {
        const status = document.createElement('div');
        status.className = 'wa-delivery-status';
        status.style.fontSize = '11px';
        status.style.color = '#bbf7d0';
        status.style.marginTop = '3px';
        status.style.textAlign = 'right';
        status.textContent = statusLabels[msg.delivery_status] || 'Sent';
        bubble.appendChild(status);
      }

      bubble.appendChild(time);
      row.appendChild(bubble);
      container.appendChild(row);

      waLastMessageId = id;
    }

    if (data.messages.length > 0) {
      container.scrollTop = container.scrollHeight;
    }

  } catch (err) {
    console.error('WhatsApp live update error:', err);
  } finally {
    waPollingInProgress = false;
  }
}

pollWhatsAppUpdates();
setInterval(pollWhatsAppUpdates, 3000);
async function refreshWhatsAppConversationList() {
  try {
    const searchInput = document.querySelector(
      '.wa-list form input[name="search"]'
    );

    const search = searchInput ? searchInput.value : '';

    const response = await fetch(
      '/whatsapp?search=' + encodeURIComponent(search),
      {
        headers: { 'X-Requested-With': 'fetch' }
      }
    );

    if (!response.ok) return;

    const html = await response.text();
    const parsed = new DOMParser().parseFromString(html, 'text/html');

    const newList = parsed.querySelector('.wa-list');
    const currentList = document.querySelector('.wa-list');

    if (newList && currentList) {
      currentList.innerHTML = newList.innerHTML;
    }
  } catch (err) {
    console.error('WhatsApp conversation list refresh error:', err);
  }
}

setInterval(refreshWhatsAppConversationList, 5000);
let waMediaRecorder = null;
let waRecordedChunks = [];

async function startWhatsAppRecording() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true
    });

    const types = [
  'audio/ogg;codecs=opus',
  'audio/webm;codecs=opus'
];

const mimeType = types.find(type =>
  MediaRecorder.isTypeSupported(type)
);
    if (!mimeType) {
      stream.getTracks().forEach(track => track.stop());
      alert('Is browser mein supported audio recording format nahi mila.');
      return;
    }

    waRecordedChunks = [];
    waMediaRecorder = new MediaRecorder(stream, { mimeType });

    waMediaRecorder.ondataavailable = event => {
      if (event.data.size > 0) {
        waRecordedChunks.push(event.data);
      }
    };

    waMediaRecorder.onstop = () => {
      const blob = new Blob(waRecordedChunks, { type: mimeType });
      const extension = mimeType.includes('ogg') ? 'ogg'
        : mimeType.includes('mp4') ? 'm4a' : 'webm';

      const audioUrl = URL.createObjectURL(blob);
      const preview = document.getElementById('waRecordingPreview');

      preview.src = audioUrl;
      preview.style.display = 'block';
      preview.dataset.extension = extension;
      preview.dataset.mimeType = mimeType;

      document.getElementById('waRecordingStatus').textContent =
        'Recording ready. Preview suno, phir Send Audio ke liye taiyar raho.';

      stream.getTracks().forEach(track => track.stop());
    };

    waMediaRecorder.start();

    document.getElementById('waRecordBtn').disabled = true;
    document.getElementById('waStopRecordBtn').disabled = false;
    document.getElementById('waRecordingStatus').textContent =
      'Recording...';

  } catch (error) {
    console.error('Audio recording error:', error);
    alert('Microphone access nahi mila. Browser ki microphone permission check karo.');
  }
}

function stopWhatsAppRecording() {
  if (waMediaRecorder && waMediaRecorder.state === 'recording') {
    waMediaRecorder.stop();
    document.getElementById('waRecordBtn').disabled = false;
    document.getElementById('waStopRecordBtn').disabled = true;
  }
}


async function sendWhatsAppMessage(event) {
  event.preventDefault();

  const input = document.getElementById('waMessage');
  const fileInput = document.getElementById('waMediaFile');
  const message = input.value.trim();
  const file = fileInput.files[0];
const recordingPreview = document.getElementById('waRecordingPreview');
 if (!message && !file && !recordingPreview.src) {
    alert('Message likho ya photo/audio select karo.');
    return false;
  }

  try {
    let response;
if (recordingPreview.src && recordingPreview.src.startsWith('blob:')) {
  const audioBlob = await fetch(recordingPreview.src).then(response => response.blob());

  const extension = recordingPreview.dataset.extension || 'ogg';
  const mimeType = recordingPreview.dataset.mimeType || audioBlob.type;

  const recordedFile = new File(
    [audioBlob],
    'recorded-audio.' + extension,
    { type: mimeType }
  );

  const formData = new FormData();
  formData.append('to', waSelectedPhone);
  formData.append('file', recordedFile);

  if (message) {
    formData.append('caption', message);
  }

  const response = await fetch('/whatsapp/send-media', {
    method: 'POST',
    body: formData
  });

  const data = await response.json();

  if (!response.ok) {
    alert('Audio send failed: ' + JSON.stringify(data.error || data));
    return false;
  }

  input.value = '';
  fileInput.value = '';
  recordingPreview.removeAttribute('src');
  recordingPreview.style.display = 'none';
  document.getElementById('waRecordingStatus').textContent = '';

  pollWhatsAppUpdates();
  return false;
}
    if (file) {
      const formData = new FormData();
      formData.append('to', waSelectedPhone);
      formData.append('file', file);

      if (message) {
        formData.append('caption', message);
      }

      response = await fetch('/whatsapp/send-media', {
        method: 'POST',
        body: formData
      });
    } else {
      response = await fetch('/whatsapp/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          to: waSelectedPhone,
          message: message
        })
      });
    }

    const data = await response.json();

    if (!response.ok) {
      alert('Message failed: ' + JSON.stringify(data.error));
      return false;
    }

    input.value = '';
    fileInput.value = '';

   // Success popup removed
    pollWhatsAppUpdates();

  } catch (err) {
    console.error('WhatsApp send error:', err);
    alert('Message send nahi hua. Server log check karo.');
  }

  return false;
}

                </script>

              `
              : ''
          }

        </div>

      </div>

    `;

    res.send(
      page(
        'WhatsApp Chat',
        content,
        'whatsapp',
        req.session.user.username
      )
    );

  } catch (err) {

    console.error(
      'WhatsApp page error:',
      err
    );

    res.status(500).send(
      'WhatsApp page error: ' +
      esc(err.message)
    );

  }
});

app.get('/whatsapp/updates', requireLogin, async function(req, res) {
  try {
   const phone = String(req.query.phone || '').trim();
const phoneNumberId = String(req.query.phone_number_id || '').trim();
const requestedClientId = String(req.query.client_id || '').trim();
const after = Number(req.query.after || 0);

if (
  !phone ||
  !phoneNumberId ||
  !Number.isSafeInteger(after) ||
  after < 0
) {
  return res.status(400).json({
    success: false,
    error: 'Invalid conversation or message ID'
  });
}


const isAdmin = req.session.user.role === 'admin';
let conversationClientId;

if (isAdmin) {
  // Admin may access only the global WhatsApp inbox.
  if (requestedClientId !== 'global') {
    return res.status(403).json({
      success: false,
      error: 'Admin cannot access client WhatsApp conversations'
    });
  }

  conversationClientId = null;
} else {
  conversationClientId = Number(req.session.user.client_id);

  if (
    !Number.isSafeInteger(conversationClientId) ||
    conversationClientId <= 0
  ) {
    return res.status(403).json({
      success: false,
      error: 'Valid client account is required'
    });
  }
}

const query = `
  SELECT
    id,
    phone,
    message,
    direction,
    created_at,
    delivery_status,
    media_id,
    media_type,
    media_mime_type
  FROM whatsapp_messages
  WHERE phone = $1
    AND phone_number_id = $2
    AND id > $3
    AND client_id IS NOT DISTINCT FROM $4::integer
  ORDER BY id ASC
  LIMIT 100
`;

const params = [
  phone,
  phoneNumberId,
  after,
  conversationClientId
];

const result = await pool.query(query, params);

const statusQuery = `
  SELECT id, delivery_status
  FROM whatsapp_messages
  WHERE phone = $1
    AND phone_number_id = $2
    AND direction = 'outgoing'
    AND client_id IS NOT DISTINCT FROM $3::integer
  ORDER BY id DESC
  LIMIT 200
`;

const statusParams = [
  phone,
  phoneNumberId,
  conversationClientId
];

const statusResult = await pool.query(
  statusQuery,
  statusParams
);
    return res.json({
      success: true,
      messages: result.rows,
      statuses: statusResult.rows
    });
  } catch (err) {
    console.error('WhatsApp updates error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not load new messages'
    });
  }
});

app.post('/whatsapp/send', requireLogin, async function(req, res) {

  try {
    const to = String(req.body.to || '').trim();
    const message = String(req.body.message || '').trim();

    if (!to || !message) {
      return res.status(400).json({
        success: false,
        error: 'Phone number and message are required'
      });
    }

    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    let token;
    let phoneNumberId;

    if (isAdmin) {
      // Admin uses the existing global WhatsApp configuration.
      token = process.env.WHATSAPP_ACCESS_TOKEN;
      phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    } else {
      // A client must have a valid client_id.
      if (!clientId) {
        return res.status(403).json({
          success: false,
          error: 'Client account is not linked correctly'
        });
      }

      const settingsResult = await pool.query(
        `SELECT phone_number_id, access_token
         FROM client_whatsapp_settings
         WHERE client_id = $1
           AND is_active = TRUE
         LIMIT 1`,
        [clientId]
      );

      if (!settingsResult.rows.length) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp is not configured for this client'
        });
      }

      phoneNumberId = settingsResult.rows[0].phone_number_id;
      token = settingsResult.rows[0].access_token;
    }

    if (!token || !phoneNumberId) {
      return res.status(500).json({
        success: false,
        error: 'WhatsApp API is not configured'
      });
    }

    const response = await fetch(
      `https://graph.facebook.com/v23.0/${phoneNumberId}/messages`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: to,
          type: 'text',
          text: { body: message }
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('WhatsApp API error:', data);
      return res.status(response.status).json({
        success: false,
        error: data
      });
    }


    await pool.query(
      `INSERT INTO whatsapp_messages
       (client_id, phone_number_id, phone, message,
        direction, whatsapp_message_id, delivery_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        isAdmin ? null : clientId,
        phoneNumberId,
        to,
        message,
        'outgoing',
        data.messages?.[0]?.id || null,
        'accepted'
      ]
    );

    return res.json({
      success: true,
      message: 'WhatsApp message sent',
      data: data
    });

  } catch (err) {
    console.error('WhatsApp send error:', err);

    return res.status(500).json({
      success: false,
      error: 'Unable to send WhatsApp message'
    });
  }
});
app.post('/whatsapp/send-media', requireLogin, whatsappUpload.single('file'), async function(req, res) {
  try {
    const to = String(req.body.to || '').trim();
    const caption = String(req.body.caption || '').trim();
    const file = req.file;

if (!to || !file) {
  return res.status(400).json({
    success: false,
    error: 'Phone number and file are required'
  });
}

let uploadBuffer = file.buffer;
    let uploadMimeType = file.mimetype;
    let uploadFileName = file.originalname;

    if (file.mimetype.startsWith('audio/')) {
      const converted = await new Promise((resolve, reject) => {
        const ffmpegProcess = spawn(ffmpegPath, [
          '-hide_banner',
          '-loglevel', 'error',
          '-i', 'pipe:0',
          '-vn',
          '-c:a', 'libopus',
          '-b:a', '64k',
          '-f', 'ogg',
          'pipe:1'
        ], {
          stdio: ['pipe', 'pipe', 'pipe']
        });

        const chunks = [];
        const errors = [];

        ffmpegProcess.stdout.on('data', chunk => chunks.push(chunk));
        ffmpegProcess.stderr.on('data', chunk => errors.push(chunk));

        ffmpegProcess.on('error', reject);

        ffmpegProcess.on('close', code => {
          if (code !== 0) {
            reject(new Error(Buffer.concat(errors).toString() || 'Audio conversion failed'));
          } else {
            resolve(Buffer.concat(chunks));
          }
        });

        ffmpegProcess.stdin.end(file.buffer);
      });

      uploadBuffer = converted;
     uploadMimeType = 'audio/ogg; codecs=opus';
      uploadFileName = 'recorded-audio.ogg';
    }


    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    let token;
    let phoneNumberId;

    if (isAdmin) {
      token = process.env.WHATSAPP_ACCESS_TOKEN;
      phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
    } else {
      if (!clientId) {
        return res.status(403).json({
          success: false,
          error: 'Client account is not linked correctly'
        });
      }

      const settingsResult = await pool.query(
        `SELECT phone_number_id, access_token
         FROM client_whatsapp_settings
         WHERE client_id = $1 AND is_active = TRUE
         LIMIT 1`,
        [clientId]
      );

      if (!settingsResult.rows.length) {
        return res.status(403).json({
          success: false,
          error: 'WhatsApp is not configured for this client'
        });
      }

      phoneNumberId = settingsResult.rows[0].phone_number_id;
      token = settingsResult.rows[0].access_token;
    }

    if (!token || !phoneNumberId) {
      return res.status(500).json({
        success: false,
        error: 'WhatsApp API is not configured'
      });
    }

    const isImage = file.mimetype.startsWith('image/');
    const maxSize = isImage ? 5 * 1024 * 1024 : 16 * 1024 * 1024;

    if (file.size > maxSize) {
      return res.status(400).json({
        success: false,
        error: isImage
          ? 'Image must be 5 MB or smaller'
          : 'Audio must be 16 MB or smaller'
      });
    }

    const formData = new FormData();
    formData.append('messaging_product', 'whatsapp');
    formData.append('type', uploadMimeType);
    formData.append(
      'file',
      new Blob([uploadBuffer], { type: uploadMimeType }),
    uploadFileName
    );

    const uploadResponse = await fetch(
      `https://graph.facebook.com/v23.0/${phoneNumberId}/media`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      }
    );

    const uploadData = await uploadResponse.json();

    if (!uploadResponse.ok || !uploadData.id) {
      console.error('WhatsApp media upload error:', uploadData);
      return res.status(502).json({
        success: false,
        error: uploadData
      });
    }

    const mediaId = uploadData.id;
    const mediaType = isImage ? 'image' : 'audio';

    const mediaMessage = {
      messaging_product: 'whatsapp',
      to: to,
      type: mediaType
    };

    if (isImage) {
      mediaMessage.image = { id: mediaId };
      if (caption) {
        mediaMessage.image.caption = caption;
      }
    } else {
      mediaMessage.audio = { id: mediaId };
    }

    const sendResponse = await fetch(
      `https://graph.facebook.com/v23.0/${phoneNumberId}/messages`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(mediaMessage)
      }
    );

    const sendData = await sendResponse.json();

    if (!sendResponse.ok) {
      console.error('WhatsApp media send error:', sendData);
      return res.status(502).json({
        success: false,
        error: sendData
      });
    }

    const savedMessage = isImage
      ? (caption || '[Photo]')
      : '[Audio]';

    await pool.query(
      `INSERT INTO whatsapp_messages
       (client_id, phone_number_id, phone, message, direction,
        whatsapp_message_id, media_type, media_id, media_mime_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        isAdmin ? null : clientId,
        phoneNumberId,
        to,
        savedMessage,
        'outgoing',
        sendData.messages?.[0]?.id || null,
        mediaType,
                mediaId,
        uploadMimeType
      ]
    );

    return res.json({
      success: true,
      message: 'WhatsApp media sent',
      mediaType: mediaType,
      data: sendData
    });

  } catch (err) {
    console.error('WhatsApp media send error:', err);
    return res.status(500).json({
      success: false,
      error: 'Unable to send WhatsApp media'
    });
  }
});

app.get('/whatsapp/media/:mediaId', requireLogin, async function(req, res) {
  try {
    const mediaId = req.params.mediaId;

    if (!/^[a-zA-Z0-9_-]+$/.test(mediaId)) {
      return res.status(400).send('Invalid media ID');
    }

    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

    let result;

    if (isAdmin) {
      result = await pool.query(
       `SELECT media_id, media_mime_type, phone_number_id, client_id
 FROM whatsapp_messages
 WHERE media_id = $1
   AND client_id IS NULL
 LIMIT 1`,
[mediaId]
      );
    } else {
      result = await pool.query(
        `SELECT media_id, media_mime_type, phone_number_id, client_id
         FROM whatsapp_messages
         WHERE media_id = $1 AND client_id = $2
         LIMIT 1`,
        [mediaId, clientId]
      );
    }

    if (!result.rows.length) {
      return res.status(404).send('Media not found');
    }

    const media = result.rows[0];
    let accessToken;

    if (isAdmin) {
      accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
    } else {
      const settings = await pool.query(
        `SELECT access_token
         FROM client_whatsapp_settings
         WHERE client_id = $1 AND is_active = true
         LIMIT 1`,
        [clientId]
      );

      accessToken = settings.rows[0]?.access_token;
    }

    if (!accessToken) {
      return res.status(403).send('WhatsApp access is not configured');
    }

    const metaResponse = await fetch(
      `https://graph.facebook.com/v23.0/${mediaId}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    if (!metaResponse.ok) {
      return res.status(502).send('Unable to retrieve media information');
    }

    const meta = await metaResponse.json();

    if (!meta.url) {
      return res.status(502).send('Media URL unavailable');
    }

    const fileResponse = await fetch(meta.url, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!fileResponse.ok || !fileResponse.body) {
      return res.status(502).send('Unable to retrieve media file');
    }

    res.setHeader(
      'Content-Type',
      media.media_mime_type || meta.mime_type || 'application/octet-stream'
    );
    res.setHeader('Cache-Control', 'private, no-store');

    return res.send(Buffer.from(await fileResponse.arrayBuffer()));
  } catch (err) {
    console.error('WhatsApp media retrieval error:', err);
    return res.status(500).send('Unable to load media');
  }
});

/* PUBLIC API */

app.get('/health', async function(req, res) {

  try {

    await pool.query('SELECT 1');

    res.json({
      status: 'ok',
      database: 'connected'
    });

  } catch (err) {

    res.status(500).json({
      status: 'error',
      database: 'disconnected'
    });
  }

});

app.get('/api/customers', requireApiKey, async function(req, res) {
  try {
    let result;

    if (req.apiRole === 'admin') {
      result = await pool.query(`
        SELECT *
        FROM customers
        ORDER BY created_at DESC
      `);
    } else if (req.apiRole === 'client' && req.apiClientId) {
      result = await pool.query(
        `
        SELECT *
        FROM customers
        WHERE client_id = $1
        ORDER BY created_at DESC
        `,
        [req.apiClientId]
      );
    } else {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    return res.json({
      success: true,
      count: result.rows.length,
      customers: result.rows
    });
  } catch (err) {
    console.error('API customer list error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not load customers'
    });
  }
});

app.post('/api/customers', requireApiKey, async function(req, res) {
  try {
    const name = String(req.body.name || '').trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        error: 'name is required'
      });
    }

    let clientId;

    if (req.apiRole === 'admin') {
      clientId = Number(req.body.client_id);

      if (!Number.isSafeInteger(clientId) || clientId <= 0) {
        return res.status(400).json({
          success: false,
          error: 'valid client_id is required'
        });
      }
    } else if (req.apiRole === 'client' && req.apiClientId) {
      clientId = req.apiClientId;
    } else {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const result = await pool.query(
      `INSERT INTO customers
       (client_id, name, phone, email, address)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        clientId,
        name,
        req.body.phone || '',
        req.body.email || '',
        req.body.address || ''
      ]
    );

    return res.status(201).json({
      success: true,
      customer: result.rows[0]
    });
  } catch (err) {
    console.error('API customer add error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not add customer'
    });
  }
});


app.put('/api/customers/:id', requireApiKey, async function(req, res) {
  try {
    const customerId = Number(req.params.id);
    if (!Number.isSafeInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'valid customer id is required'
      });
    }

    const name = String(req.body.name || '').trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        error: 'name is required'
      });
    }

    let result;

    if (req.apiRole === 'admin') {
      result = await pool.query(
        `
        UPDATE customers
        SET name=$1, phone=$2, email=$3, address=$4
        WHERE id=$5
        RETURNING *
        `,
        [
          name,
          req.body.phone || '',
          req.body.email || '',
          req.body.address || '',
          customerId
        ]
      );
    } else if (req.apiRole === 'client' && req.apiClientId) {
      result = await pool.query(
        `
        UPDATE customers
        SET name=$1, phone=$2, email=$3, address=$4
        WHERE id=$5 AND client_id=$6
        RETURNING *
        `,
        [
          name,
          req.body.phone || '',
          req.body.email || '',
          req.body.address || '',
          customerId,
          req.apiClientId
        ]
      );
    } else {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    if (!result.rows[0]) {
      return res.status(404).json({
        success: false,
        error: 'Customer not found'
      });
    }

    return res.json({
      success: true,
      customer: result.rows[0]
    });
  } catch (err) {
    console.error('API customer update error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not update customer'
    });
  }
});


app.delete('/api/customers/:id', requireApiKey, async function(req, res) {
  try {
    const customerId = Number(req.params.id);

    if (!Number.isSafeInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'valid customer id is required'
      });
    }

    let result;

    if (req.apiRole === 'admin') {
      result = await pool.query(
        `
        DELETE FROM customers
        WHERE id=$1
        RETURNING *
        `,
        [customerId]
      );
    } else if (req.apiRole === 'client' && req.apiClientId) {
      result = await pool.query(
        `
        DELETE FROM customers
        WHERE id=$1 AND client_id=$2
        RETURNING *
        `,
        [customerId, req.apiClientId]
      );
    } else {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    if (!result.rows[0]) {
      return res.status(404).json({
        success: false,
        error: 'Customer not found'
      });
    }

    return res.json({
      success: true,
      message: 'Customer deleted successfully',
      customer: result.rows[0]
    });
  } catch (err) {
    console.error('API customer delete error:', err);

    return res.status(500).json({
      success: false,
      error: 'Could not delete customer'
    });
  }
});
app.put('/api/leads/:id', requireApiKey, async function(req, res) {

  try {

    const leadId = Number(req.params.id);

    if (!leadId) {

      return res.status(400).json({
        success: false,
        error: 'valid lead id is required'
      });

    }

    const name = String(req.body.name || '').trim();

    if (!name) {

      return res.status(400).json({
        success: false,
        error: 'name is required'
      });

    }

    let result;

    if (req.apiClientId) {

      result = await pool.query(
        `
        UPDATE leads
        SET name=$1,
            phone=$2,
            email=$3,
            source=$4,
            status=$5,
            follow_up=$6,
            notes=$7
        WHERE id=$8
          AND client_id=$9
        RETURNING *
        `,
        [
          name,
          req.body.phone || '',
          req.body.email || '',
          req.body.source || 'Other',
          req.body.status || 'New',
          req.body.follow_up || null,
          req.body.notes || '',
          leadId,
          req.apiClientId
        ]
      );

    } else {

      result = await pool.query(
        `
        UPDATE leads
        SET name=$1,
            phone=$2,
            email=$3,
            source=$4,
            status=$5,
            follow_up=$6,
            notes=$7
        WHERE id=$8
        RETURNING *
        `,
        [
          name,
          req.body.phone || '',
          req.body.email || '',
          req.body.source || 'Other',
          req.body.status || 'New',
          req.body.follow_up || null,
          req.body.notes || '',
          leadId
        ]
      );

    }

    if (!result.rows[0]) {

      return res.status(404).json({
        success: false,
        error: 'Lead not found'
      });

    }

    res.json({
      success: true,
      lead: result.rows[0]
    });

  } catch (err) {

    console.error('API lead update error:', err);

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});
app.delete('/api/leads/:id', requireApiKey, async function(req, res) {

  try {

    const leadId = Number(req.params.id);

    if (!leadId) {

      return res.status(400).json({
        success: false,
        error: 'valid lead id is required'
      });

    }

    let result;

    if (req.apiClientId) {

      result = await pool.query(
        `
        DELETE FROM leads
        WHERE id=$1
          AND client_id=$2
        RETURNING *
        `,
        [
          leadId,
          req.apiClientId
        ]
      );

    } else {

      result = await pool.query(
        `
        DELETE FROM leads
        WHERE id=$1
        RETURNING *
        `,
        [
          leadId
        ]
      );

    }

    if (!result.rows[0]) {

      return res.status(404).json({
        success: false,
        error: 'Lead not found'
      });

    }

    res.json({
      success: true,
      message: 'Lead deleted successfully',
      lead: result.rows[0]
    });

  } catch (err) {

    console.error('API lead delete error:', err);

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});
  app.get('/api/leads', requireApiKey, async function(req, res) {
  try {

    let result;

    if (req.apiClientId) {

      result = await pool.query(
        `
        SELECT *
        FROM leads
        WHERE client_id=$1
        ORDER BY created_at DESC
        `,
        [req.apiClientId]
      );

    } else {

      result = await pool.query(`
        SELECT *
        FROM leads
        ORDER BY created_at DESC
      `);

    }

    res.json({
      success: true,
      count: result.rows.length,
      leads: result.rows
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});
app.post('/api/leads', requireApiKey, async function(req, res) {
  try {

    const name = String(req.body.name || '').trim();

    if (!name) {

      return res.status(400).json({
        success: false,
        error: 'name is required'
      });
    }

    let clientId;

    // Client API key
    if (req.apiClientId) {

      clientId = req.apiClientId;

    } else {

      // Global API key
      clientId = Number(req.body.client_id);

      if (!clientId) {
        return res.status(400).json({
          success: false,
          error: 'client_id is required'
        });
      }

    }

    const result = await pool.query(
      `INSERT INTO leads
       (client_id,name,phone,email,source,status,follow_up,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING *`,
      [
        clientId,
        name,
        req.body.phone || '',
        req.body.email || '',
        req.body.source || 'Other',
        req.body.status || 'New',
        req.body.follow_up || null,
        req.body.notes || ''
      ]
    );

    res.status(201).json({
      success: true,
      lead: result.rows[0]
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});
/* START */

(async function start() {

  try {

    if (process.env.DATABASE_URL) {
      await setupDatabase();
    }

    app.listen(PORT, function() {

      console.log(
        'CRM API running on port ' + PORT
      );

    });

  } catch (err) {

    console.error(
      'Database setup failed:',
      err.message
    );

    process.exit(1);
  }

})();
