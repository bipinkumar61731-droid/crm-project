const express = require('express');
const session = require('express-session');
const pg = require('pg');

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL missing. Add it on Render Environment Variables.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
function requireApiKey(req, res, next) {

  const apiKey = req.headers['x-api-key'];

  const validApiKey = process.env.CRM_API_KEY;

  if (!validApiKey) {
    return res.status(500).json({
      success: false,
      error: 'API key is not configured'
    });
  }

  if (!apiKey || apiKey !== validApiKey) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key'
    });
  }

  next();
}
app.use(session({
  secret: process.env.SESSION_SECRET || 'crm-secret-change-this',
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

function page(title, content, active, username) {
  const nav = [
    ['/', 'Dashboard', 'dashboard'],
    ['/customers', 'Customers', 'customers'],
    ['/leads', 'Leads', 'leads'],
    ['/followups', 'Follow-ups', 'followups'],
    ['/staff', 'Staff', 'staff'],
['/clients', 'Clients', 'clients'],
    ['/api-info', 'API', 'api'],
    ['/whatsapp', '💬 WhatsApp Chat', 'whatsapp']
  ];

  let links = '';
  for (const item of nav) {
    links +=
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

@media(max-width:600px){
  .main{
    padding:15px;
  }

  .grid,
  .form-grid,
  .quick{
    grid-template-columns:1fr;
  }

  .topbar{
    align-items:flex-start;
    flex-direction:column;
  }

  table{
    font-size:13px;
  }

  th,td{
    padding:9px 6px;
  }

  .table-wrap{
    overflow-x:auto;
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
    👤 ${esc(username || 'Admin')}
  </div>
</div>

${content}

</main>
</div>

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
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'staff'
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
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
  `);
await pool.query(
    `INSERT INTO users(username,password,role)
     VALUES($1,$2,$3)
     ON CONFLICT(username)
     DO UPDATE SET password=EXCLUDED.password,
                   role=EXCLUDED.role`,
    ['admin', 'Admin@123', 'admin']
  );
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
  ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT FALSE
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

app.post('/login', async function(req, res) {

  try {

    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1 AND password=$2',
      [req.body.username, req.body.password]
    );

    if (!result.rows[0]) {
      return res.redirect('/login?error=1');
    }

    const user = result.rows[0];

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

  req.session.destroy(function() {
    res.redirect('/login');
  });

});

/* DASHBOARD */
app.get('/', requireLogin, async function(req, res) {
  try {
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
      pool.query('SELECT COUNT(*)::int AS count FROM customers'),
      pool.query('SELECT COUNT(*)::int AS count FROM leads'),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='New'"),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='Contacted'"),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='Interested'"),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='Follow-up'"),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='Converted'"),
      pool.query("SELECT COUNT(*)::int AS count FROM leads WHERE status='Lost'"),
      pool.query(`
        SELECT COUNT(*)::int AS count
        FROM leads
        WHERE follow_up IS NOT NULL
        AND follow_up >= CURRENT_DATE
      `),
      pool.query(`
        SELECT COALESCE(source, 'Other') AS source, COUNT(*)::int AS count
        FROM leads
        GROUP BY source
        ORDER BY count DESC
      `),
      pool.query(`
        SELECT id, name, phone, source, status, follow_up, notes
        FROM leads
        ORDER BY id DESC
        LIMIT 8
      `),
pool.query(`
        SELECT id, phone, message, direction, created_at
        FROM whatsapp_messages
        ORDER BY id DESC
        LIMIT 10
      `)
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
                📞 Call
              </a>
              <a href="https://wa.me/${String(lead.phone).replace(/[^0-9]/g, '')}" target="_blank" class="badge status" style="text-decoration:none;">
                💬 WhatsApp
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
      </style>

      <div class="dash-head">
        <div>
          <h1>Dashboard</h1>
          <p>Welcome back! Here's what's happening with your CRM.</p>
        </div>

        <div class="dash-actions">
          <a class="dash-btn" href="/leads/add">+ Add Lead</a>
          <a class="dash-btn secondary" href="/customers/add">+ Customer</a>
        </div>
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
  <h2>⚡ Quick Actions</h2>
  <div class="action-buttons">
    <a href="/leads/add" class="action-btn">➕ Add Lead</a>
    <a href="/customers/add" class="action-btn">👤 Add Customer</a>
    <a href="/followups" class="action-btn">📅 Follow-ups</a>
    <a href="/api-info" class="action-btn">🔗 API Info</a>
  </div>
</div>

<div class="status-box">
  <h2>📱 WhatsApp & API Status</h2>
  <div class="status-item">
    <span>WhatsApp Business API</span>
    <strong>⚪ Not Connected</strong>
  </div>
  <div class="status-item">
    <span>CRM API</span>
    <strong>🟢 Running</strong>
  </div>
</div>
<div class="today-box">
  <h2>📌 Today's Follow-ups</h2>
  <p>Check today's scheduled follow-ups.</p>

  <div class="action-buttons">
    <a href="/followups" class="action-btn">View Follow-ups →</a>
    <a href="/leads" class="action-btn">View All Leads →</a>
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

    alert('WhatsApp message sent successfully!');
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

    res.send(page('Dashboard', content));

  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('Dashboard error: ' + err.message);
  }
});

/* CUSTOMERS */
app.post('/customers/edit/:id', requireLogin, async function(req, res) {

  try {

    const customerId = Number(req.params.id);
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

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
    const isAdmin = req.session.user.role === 'admin';
    const clientId = req.session.user.client_id;

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

    let result;

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
        req.session.user.username
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
        req.session.user.username
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
const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;

if (isAdmin) {

  await pool.query(
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

  await pool.query(
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
const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;

if (isAdmin) {

  await pool.query(
    'DELETE FROM leads WHERE id=$1',
    [leadId]
  );

} else {

  await pool.query(
    'DELETE FROM leads WHERE id=$1 AND client_id=$2',
    [leadId, clientId]
  );

}
    res.redirect('/leads');

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Delete lead error: ' + esc(err.message)
    );
  }

});

/* FOLLOW UPS */

app.get('/followups', requireLogin, async function(req, res) {

  try {

   const isAdmin = req.session.user.role === 'admin';
const clientId = req.session.user.client_id;

let result;

if (isAdmin) {

  result = await pool.query(`
    SELECT *
    FROM leads
    WHERE follow_up IS NOT NULL
    AND status NOT IN ('Converted','Lost')
    ORDER BY follow_up ASC
  `);

} else {

  result = await pool.query(
    `
    SELECT *
    FROM leads
    WHERE follow_up IS NOT NULL
    AND status NOT IN ('Converted','Lost')
    AND client_id=$1
    ORDER BY follow_up ASC
    `,
    [clientId]
  );

}
    let rows = '';

    result.rows.forEach(function(lead) {

      const date = new Date(lead.follow_up)
        .toISOString()
        .slice(0,10);

      const overdue =
        new Date(lead.follow_up) < new Date();

      rows += `
      <tr>

      <td>${esc(lead.name)}</td>

      <td>${esc(lead.phone)}</td>

      <td>${esc(lead.status)}</td>

      <td>
      <span class="badge">
      ${esc(date)}
      </span>
      ${overdue ? '<span class="badge">Overdue</span>' : ''}
      </td>

      <td>
      <a class="btn btn-gray"
         href="/leads?edit=${lead.id}">
      Open
      </a>
      </td>

      </tr>
      `;
    });

    if (!rows) {
      rows =
        '<tr><td colspan="5" class="muted">No follow-ups scheduled.</td></tr>';
    }

    const content = `

<div class="card">

<h2>Follow-up List</h2>

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

<tbody>
${rows}
</tbody>

</table>

</div>

</div>
`;

    res.send(
      page(
        'Follow-ups',
        content,
        'followups',
        req.session.user.username
      )
    );

  } catch (err) {

    console.error(err);

    res.status(500).send(
      'Follow-ups error: ' + esc(err.message)
    );
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

    await pool.query(
      `INSERT INTO users(username,password,role)
       VALUES($1,$2,$3)`,
      [
        String(req.body.username || '').trim(),
        String(req.body.password || ''),
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

    if (!newPassword) {
      return res.status(400).send('Password required');
    }

    await pool.query(
      `UPDATE users
       SET password=$1
       WHERE id=$2`,
      [newPassword, userId]
    );

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
    const result = await pool.query(`
      SELECT id, name, email, phone, status, created_at
      FROM clients
      ORDER BY id DESC
    `);

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
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim();
    const phone = String(req.body.phone || '').trim();
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '').trim();

    if (!name) {
      return res.status(400).send('Client name required');
    }

    if (!username || !password) {
      return res.status(400).send('Username and password required');
    }

    const clientResult = await pool.query(
      `
      INSERT INTO clients(name, email, phone, status)
      VALUES($1, $2, $3, 'active')
      RETURNING id
      `,
      [name, email, phone]
    );

    const clientId = clientResult.rows[0].id;

    await pool.query(
      `
      INSERT INTO users(username, password, role, client_id)
      VALUES($1, $2, 'client', $3)
      `,
      [username, password, clientId]
    );

    res.redirect('/clients');

  } catch (err) {
    console.error('Add client error:', err);

    res.status(500).send(
      'Unable to add client: ' + err.message
    );
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

  const verifyToken = process.env.WHATSAPP_VERIFY_TOKEN || 'crm-whatsapp-verify';

  if (mode === 'subscribe' && token === verifyToken) {
    return res.status(200).send(challenge);
  }

  res.sendStatus(403);
});
app.post('/webhook/whatsapp', async function(req, res) {
  try {
    console.log('WhatsApp webhook received');

    const value = req.body?.entry?.[0]?.changes?.[0]?.value;
    const messages = value?.messages || [];

    for (const msg of messages) {
      const phone = msg.from || '';
      const whatsappMessageId = msg.id || '';

      let message = '';

      if (msg.type === 'text') {
        message = msg.text?.body || '';
      } else {
        message = `[${msg.type || 'unknown'} message]`;
      }

      if (!phone) continue;

      await pool.query(
        `INSERT INTO whatsapp_messages
         (phone, message, direction, whatsapp_message_id)
         VALUES ($1, $2, $3, $4)`,
        [phone, message, 'incoming', whatsappMessageId]
      );

      console.log('Incoming WhatsApp message saved:', {
        phone,
        message
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

app.get('/whatsapp', requireLogin, async function(req, res) {
  try {
    const search = String(req.query.search || '').trim();
    const selectedPhone = String(req.query.phone || '').trim();

    // Mark selected conversation as read first
    if (selectedPhone) {
      await pool.query(
        `
        UPDATE whatsapp_messages
        SET is_read = true
        WHERE phone = $1
          AND direction = 'incoming'
        `,
        [selectedPhone]
      );
    }

    // Conversation list
    let conversationsQuery = `
      SELECT
        phone,
        MAX(id) AS last_id,
        MAX(created_at) AS last_time,
        COUNT(*)::int AS message_count,
        COUNT(*) FILTER (
          WHERE direction = 'incoming'
          AND is_read = false
        )::int AS unread_count
      FROM whatsapp_messages
    `;

    const params = [];

    if (search) {
      params.push('%' + search + '%');

      conversationsQuery += `
        WHERE phone ILIKE $1
      `;
    }

    conversationsQuery += `
      GROUP BY phone
      ORDER BY last_id DESC
    `;

    const conversationsResult =
      await pool.query(conversationsQuery, params);

    let phone = selectedPhone;

    if (!phone && conversationsResult.rows.length) {
      phone = conversationsResult.rows[0].phone;
    }

    // Messages of selected conversation
    let messages = [];

    if (phone) {
      const messageResult = await pool.query(
        `
        SELECT
          id,
          phone,
          message,
          direction,
          whatsapp_message_id,
          created_at
        FROM whatsapp_messages
        WHERE phone = $1
        ORDER BY id ASC
        `,
        [phone]
      );

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
          <a
            href="/whatsapp?phone=${encodeURIComponent(chat.phone)}"
            style="
              display:block;
              padding:14px;
              border-bottom:1px solid #26304a;
              text-decoration:none;
              color:white;
              ${active}
            "
          >

            <div style="
              display:flex;
              justify-content:space-between;
              gap:8px;
            ">

              <strong>
                📱 ${esc(chat.phone)}
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
        `;

      }).join('');

    // Message bubbles
    const messageRows =
      messages.map(msg => {

        const incoming =
          msg.direction === 'incoming';

        return `
          <div style="
            display:flex;
            justify-content:${incoming
              ? 'flex-start'
              : 'flex-end'};
            margin-bottom:10px;
          ">

            <div style="
              max-width:75%;
              padding:11px 14px;
              border-radius:14px;
              background:${incoming
                ? '#1e293b'
                : '#166534'};
              color:white;
            ">

              <div style="
                font-size:14px;
                line-height:1.45;
                white-space:pre-wrap;
              ">
                ${esc(msg.message || '-')}
              </div>

              <div style="
                font-size:10px;
                color:#cbd5e1;
                margin-top:5px;
                text-align:right;
              ">
                ${esc(
                  new Date(
                    msg.created_at
                  ).toLocaleString()
                )}
              </div>

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

      </style>

      <div class="wa-layout">

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
                ? `💬 WhatsApp — ${esc(phone)}`
                : '💬 WhatsApp Inbox'
            }

          </div>


          <!-- MESSAGES -->

          <div class="wa-messages">

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
                  >

                    <input
                      id="waMessage"
                      placeholder="Type a message..."
                      autocomplete="off"
                      required
                    >

                    <button
                      class="btn"
                      type="submit"
                    >
                      Send
                    </button>

                  </form>

                </div>


                <script>

                  async function sendWhatsAppMessage(event) {

                    event.preventDefault();

                    const input =
                      document.getElementById(
                        'waMessage'
                      );

                    const message =
                      input.value.trim();

                    if (!message) {
                      return false;
                    }

                    try {

                      const response =
                        await fetch(
                          '/whatsapp/send',
                          {
                            method:'POST',

                            headers:{
                              'Content-Type':
                                'application/json'
                            },

                            body:JSON.stringify({
                              to:${JSON.stringify(phone)},
                              message:message
                            })
                          }
                        );

                      const data =
                        await response.json();

                      if (!response.ok) {

                        alert(
                          'Message failed: ' +
                          JSON.stringify(
                            data.error
                          )
                        );

                        return false;
                      }

                      input.value = '';

                      location.reload();

                    } catch(err) {

                      alert(
                        'Error sending WhatsApp message'
                      );

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

    const token = process.env.WHATSAPP_ACCESS_TOKEN;
    const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

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
          text: {
            body: message
          }
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
   (phone, message, direction, whatsapp_message_id)
   VALUES ($1, $2, $3, $4)`,
  [
    to,
    message,
    'outgoing',
    data.messages?.[0]?.id || null
  ]
);
    res.json({
      success: true,
      message: 'WhatsApp message sent',
      data: data
    });

  } catch (err) {
    console.error('WhatsApp send error:', err);

    res.status(500).json({
      success: false,
      error: err.message
    });
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

    const result = await pool.query(`
      SELECT *
      FROM customers
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      count: result.rows.length,
      customers: result.rows
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error: err.message
    });
  }

});

app.get('/api/leads', requireApiKey, async function(req, res) {
  try {

    const result = await pool.query(`
      SELECT *
      FROM leads
      ORDER BY created_at DESC
    `);

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

    const result = await pool.query(
      `INSERT INTO leads
       (name,phone,email,source,status,follow_up,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
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