const express = require('express');
const session = require('express-session');
const pg = require('pg');

const { Pool } = pg;
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

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
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SESSION_SECRET || 'crm-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
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
  return a === b ? 'selected' : '';
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

let currentUserName = 'admin';

function reqUserName() {
  return currentUserName;
}

function css() {
  return `
  *,*::before,*::after{
    box-sizing:border-box
  }

  body{
    margin:0;
    font-family:Inter,Arial,sans-serif;
    background:#0b1020;
    color:#eef2ff
  }

  a{
    text-decoration:none;
    color:inherit
  }

  .app{
    display:flex;
    min-height:100vh
  }

  .sidebar{
    width:235px;
    background:#0e1426;
    border-right:1px solid #202945;
    padding:22px 14px;
    display:flex;
    flex-direction:column;
    position:fixed;
    inset:0 auto 0 0
  }

  .brand{
    display:flex;
    gap:10px;
    align-items:center;
    padding:4px 10px 25px
  }

  .brand b{
    font-size:19px
  }

  .brand small{
    display:block;
    color:#7f8ba8;
    font-size:11px;
    margin-top:3px
  }

  .logo{
    width:38px;
    height:38px;
    border-radius:11px;
    background:linear-gradient(135deg,#6d5dfc,#25c6ff);
    display:grid;
    place-items:center;
    font-weight:800;
    font-size:20px
  }

  .nav{
    display:block;
    padding:13px;
    border-radius:10px;
    color:#9aa5c0;
    margin:4px 0;
    font-size:14px
  }

  .nav:hover,
  .nav.active{
    background:#1a2340;
    color:#fff
  }

  .sidebottom{
    margin-top:auto
  }

  .userbox{
    border-top:1px solid #202945;
    padding:15px 10px;
    color:#dce2f4
  }

  .userbox small{
    display:block;
    color:#77839f;
    margin-top:4px
  }

  .logout{
    display:block;
    padding:11px 10px;
    color:#ff8e9b;
    font-size:14px
  }

  .main{
    margin-left:235px;
    width:calc(100% - 235px);
    padding:28px 34px 45px
  }

  header{
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    margin-bottom:24px
  }

  .eyebrow{
    font-size:10px;
    color:#7180a0;
    letter-spacing:2px;
    margin-bottom:5px
  }

  h1{
    font-size:27px;
    margin:0
  }

  .topright{
    font-size:12px;
    color:#7ee2a8
  }

  .online{
    background:#10271f;
    padding:8px 11px;
    border-radius:20px
  }

  .cards{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:14px;
    margin-bottom:20px
  }

  .card,
  .panel{
    background:#11182c;
    border:1px solid #202945;
    border-radius:14px
  }

  .card{
    padding:18px
  }

  .card .label{
    color:#8290ad;
    font-size:12px
  }

  .card .num{
    font-size:29px;
    font-weight:800;
    margin-top:8px
  }

  .grid2{
    display:grid;
    grid-template-columns:1.35fr 1fr;
    gap:18px
  }

  .panel{
    padding:20px;
    margin-bottom:18px
  }

  .panel h2{
    font-size:16px;
    margin:0 0 16px
  }

  .tablewrap{
    overflow:auto
  }

  .table{
    width:100%;
    border-collapse:collapse;
    font-size:13px
  }

  .table th,
  .table td{
    text-align:left;
    padding:12px 9px;
    border-bottom:1px solid #202945;
    white-space:nowrap
  }

  .table th{
    color:#7e8ba7;
    font-weight:600
  }

  .muted{
    color:#7f8ba5
  }

  .formgrid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:12px
  }

  .formgrid.three{
    grid-template-columns:repeat(3,1fr)
  }

  label{
    font-size:12px;
    color:#8d99b2;
    display:block;
    margin-bottom:6px
  }

  input,
  select,
  textarea{
    width:100%;
    background:#0b1121;
    border:1px solid #283352;
    color:#eef2ff;
    border-radius:9px;
    padding:11px 12px;
    outline:none
  }

  textarea{
    min-height:88px;
    resize:vertical
  }

  input:focus,
  select:focus,
  textarea:focus{
    border-color:#6575ff
  }

  .btn{
    border:0;
    border-radius:9px;
    padding:11px 15px;
    background:#5967ff;
    color:white;
    font-weight:700;
    cursor:pointer
  }

  .btn.secondary{
    background:#202a46
  }

  .btn.danger{
    background:#5a2430
  }

  .actions{
    display:flex;
    gap:7px
  }

  .pill{
    display:inline-block;
    padding:5px 9px;
    border-radius:20px;
    font-size:11px;
    background:#202a46;
    color:#cbd4eb
  }

  .pill.green{
    background:#143528;
    color:#76e0a8
  }

  .pill.yellow{
    background:#3b3114;
    color:#f2d477
  }

  .pill.red{
    background:#3c2028;
    color:#ff98a8
  }

  .searchbar{
    display:flex;
    gap:10px;
    margin-bottom:15px
  }

  .searchbar input{
    max-width:360px
  }

  .statsline{
    display:flex;
    gap:10px;
    flex-wrap:wrap
  }

  .mini{
    padding:10px 13px;
    background:#0d1427;
    border:1px solid #202945;
    border-radius:9px;
    color:#aab5ca;
    font-size:12px
  }

  .empty{
    text-align:center;
    color:#73809d;
    padding:25px
  }

  .notice{
    padding:12px 14px;
    border-radius:9px;
    background:#15233a;
    color:#a9c7ff;
    margin-bottom:15px
  }

  .loginbody{
    min-height:100vh;
    display:grid;
    place-items:center;
    background:#080d19
  }

  .loginbox{
    width:min(420px,92vw);
    background:#11182c;
    border:1px solid #202945;
    border-radius:18px;
    padding:28px
  }

  .loginbox h1{
    margin-bottom:7px
  }

  .loginbox p{
    color:#7f8ba7;
    font-size:13px
  }

  .loginbox form{
    margin-top:22px
  }

  .loginbox .field{
    margin-bottom:14px
  }

  .full{
    width:100%
  }

  .error{
    background:#3a2029;
    color:#ffabb7;
    padding:10px;
    border-radius:8px;
    font-size:13px;
    margin-bottom:14px
  }

  @media(max-width:950px){
    .cards{
      grid-template-columns:repeat(2,1fr)
    }

    .grid2{
      grid-template-columns:1fr
    }
  }

  @media(max-width:700px){
    .sidebar{
      position:static;
      width:100%;
      height:auto
    }

    .app{
      display:block
    }

    .sidebar nav{
      display:flex;
      overflow:auto
    }

    .nav{
      white-space:nowrap
    }

    .sidebottom{
      display:none
    }

    .main{
      margin:0;
      width:100%;
      padding:20px 14px
    }

    .cards{
      grid-template-columns:1fr 1fr
    }

    .formgrid,
    .formgrid.three{
      grid-template-columns:1fr
    }

    header{
      align-items:center
    }

    .topright{
      display:none
    }
  }
  `;
}

function page(title, content, active) {
  const nav = [
    ['dashboard', 'Dashboard', '/'],
    ['customers', 'Customers', '/customers'],
    ['leads', 'Leads', '/leads'],
    ['followups', 'Follow-ups', '/followups'],
    ['staff', 'Staff', '/staff'],
    ['api', 'API', '/api-info']
  ];

  const links = nav.map(function(item) {
    return '<a class="nav ' +
      (active === item[0] ? 'active' : '') +
      '" href="' + item[2] + '">' +
      item[1] +
      '</a>';
  }).join('');

  return '<!doctype html>' +
    '<html>' +
    '<head>' +
    '<meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + esc(title) + ' - CRM</title>' +
    '<style>' + css() + '</style>' +
    '</head>' +
    '<body>' +
    '<div class="app">' +

    '<aside class="sidebar">' +
    '<div class="brand">' +
    '<div class="logo">C</div>' +
    '<div><b>CRM Pro</b><small>Business CRM</small></div>' +
    '</div>' +

    '<nav>' + links + '</nav>' +

    '<div class="sidebottom">' +
    '<div class="userbox">' +
    '<b>' + esc(reqUserName()) + '</b>' +
    '<small>Administrator</small>' +
    '</div>' +
    '<a class="logout" href="/logout">Logout</a>' +
    '</div>' +
    '</aside>' +

    '<main class="main">' +
    '<header>' +
    '<div>' +
    '<div class="eyebrow">CRM MANAGEMENT</div>' +
    '<h1>' + esc(title) + '</h1>' +
    '</div>' +
    '<div class="topright"><span class="online">● System Online</span></div>' +
    '</header>' +
    content +
    '</main>' +

    '</div>' +
    '</body>' +
    '</html>';
}

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'staff',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'staff'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      phone VARCHAR(50),
      email VARCHAR(150),
      address TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
await pool.query(`
  ALTER TABLE leads
  ADD COLUMN IF NOT EXISTS follow_up DATE
`);
    await pool.query(
    `INSERT INTO users(username,password,role)
     VALUES($1,$2,$3)
     ON CONFLICT(username)
     DO UPDATE SET password=EXCLUDED.password, role=EXCLUDED.role`,
    ['admin', 'Admin@123', 'admin']
  );
}

app.get('/login', function(req, res) {
  if (req.session.user) return res.redirect('/');

  const error = req.query.error
    ? '<div class="error">Username or password failed.</div>'
    : '';

  res.send(
    '<!doctype html>' +
    '<html><head>' +
    '<meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>CRM Login</title>' +
    '<style>' + css() + '</style>' +
    '</head>' +
    '<body class="loginbody">' +
    '<div class="loginbox">' +
    '<div class="brand">' +
    '<div class="logo">C</div>' +
    '<div><b>CRM Pro</b><small>Business CRM</small></div>' +
    '</div>' +
    '<h1>Welcome back</h1>' +
    '<p>Sign in to manage your CRM.</p>' +
    error +
    '<form method="post" action="/login">' +
    '<div class="field">' +
    '<label>Username</label>' +
    '<input name="username" required>' +
    '</div>' +
    '<div class="field">' +
    '<label>Password</label>' +
    '<input name="password" type="password" required>' +
    '</div>' +
    '<button class="btn full">Login</button>' +
    '</form>' +
    '</div>' +
    '</body></html>'
  );
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
        role: user.role
      };

      currentUserName = user.username;

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

function stat(label, value) {
  return '<div class="card">' +
    '<div class="label">' + label + '</div>' +
    '<div class="num">' + value + '</div>' +
    '</div>';
}

app.get('/', requireLogin, async function(req, res) {
  currentUserName = req.session.user.username;

  try {
    const q = async function(sql) {
      const r = await pool.query(sql);
      return r.rows[0].count;
    };

    const totalCustomers =
      await q('SELECT COUNT(*)::int AS count FROM customers');

    const totalLeads =
      await q('SELECT COUNT(*)::int AS count FROM leads');

    const newLeads =
      await q("SELECT COUNT(*)::int AS count FROM leads WHERE status='New'");

    const converted =
      await q("SELECT COUNT(*)::int AS count FROM leads WHERE status='Converted'");

    const pending =
      await q(`
        SELECT COUNT(*)::int AS count
        FROM leads
        WHERE follow_up IS NOT NULL
        AND follow_up <= CURRENT_DATE
        AND status NOT IN ('Converted','Lost')
      `);

    const interested =
      await q("SELECT COUNT(*)::int AS count FROM leads WHERE status='Interested'");

    const recent =
      await pool.query('SELECT * FROM leads ORDER BY id DESC LIMIT 8');

    const rows = recent.rows.map(function(l) {
      return '<tr>' +
        '<td>' + esc(l.name) + '</td>' +
        '<td>' + esc(l.phone) + '</td>' +
        '<td>' + esc(l.source) + '</td>' +
        '<td><span class="pill">' + esc(l.status) + '</span></td>' +
        '<td>' + esc(l.follow_up || '-') + '</td>' +
        '</tr>';
    }).join('');

    const content =
      '<div class="cards">' +
      stat('Customers', totalCustomers) +
      stat('Total Leads', totalLeads) +
      stat('New Leads', newLeads) +
      stat('Converted', converted) +
      '</div>' +

      '<div class="statsline" style="margin-bottom:18px">' +
      '<div class="mini">Interested: <b>' + interested + '</b></div>' +
      '<div class="mini">Pending follow-ups: <b>' + pending + '</b></div>' +
      '</div>' +

      '<div class="grid2">' +

      '<div class="panel">' +
      '<h2>Recent Leads</h2>' +
      '<div class="tablewrap">' +
      '<table class="table">' +
      '<thead><tr>' +
      '<th>Name</th><th>Phone</th><th>Source</th>' +
      '<th>Status</th><th>Follow-up</th>' +
      '</tr></thead>' +
      '<tbody>' +
      (rows ||
        '<tr><td colspan="5" class="empty">No leads yet</td></tr>') +
      '</tbody>' +
      '</table>' +
      '</div>' +
      '</div>' +

      '<div class="panel">' +
      '<h2>Quick Actions</h2>' +
      '<p class="muted">Add records and manage your sales pipeline.</p>' +
      '<div class="actions">' +
      '<a class="btn" href="/customers">Add Customer</a>' +
      '<a class="btn secondary" href="/leads">Add Lead</a>' +
      '</div>' +
      '<div class="notice" style="margin-top:18px">' +
      'WhatsApp Business, ads integrations and advanced reports can be connected in the next stages.' +
      '</div>' +
      '</div>' +

      '</div>';

    res.send(page('Dashboard', content, 'dashboard'));
  } catch (err) {
    console.error(err);
    res.status(500).send('Dashboard error: ' + esc(err.message));
  }
});

app.get('/customers', requireLogin, async function(req, res) {
  try {
    const search = String(req.query.search || '').trim();

    const result = search
      ? await pool.query(
          `SELECT * FROM customers
           WHERE name ILIKE $1
           OR phone ILIKE $1
           OR email ILIKE $1
           ORDER BY id DESC`,
          ['%' + search + '%']
        )
      : await pool.query(
          'SELECT * FROM customers ORDER BY id DESC'
        );

    const editId = req.query.edit ? Number(req.query.edit) : 0;
    let edit = null;

    if (editId) {
      const er =
        await pool.query(
          'SELECT * FROM customers WHERE id=$1',
          [editId]
        );

      edit = er.rows[0] || null;
    }

    const rows = result.rows.map(function(c) {
      return '<tr>' +
        '<td>' + esc(c.name) + '</td>' +
        '<td>' + esc(c.phone) + '</td>' +
        '<td>' + esc(c.email) + '</td>' +
        '<td>' + esc(c.address) + '</td>' +
        '<td>' +
        '<div class="actions">' +
        '<a class="btn secondary" href="/customers?edit=' +
        c.id + '">Edit</a>' +

        '<form method="post" action="/customers/delete/' +
        c.id +
        '" onsubmit="return confirm(\'Delete this customer?\')">' +
        '<button class="btn danger">Delete</button>' +
        '</form>' +

        '</div>' +
        '</td>' +
        '</tr>';
    }).join('');

    const form =
      '<div class="panel">' +
      '<h2>' +
      (edit ? 'Edit Customer' : 'Add Customer') +
      '</h2>' +

      '<form method="post" action="' +
      (edit
        ? '/customers/edit/' + edit.id
        : '/customers/add') +
      '">' +

      '<div class="formgrid">' +

      '<div>' +
      '<label>Name</label>' +
      '<input name="name" value="' +
      esc(edit ? edit.name : '') +
      '" required>' +
      '</div>' +

      '<div>' +
      '<label>Phone</label>' +
      '<input name="phone" value="' +
      esc(edit ? edit.phone : '') +
      '">' +
      '</div>' +

      '<div>' +
      '<label>Email</label>' +
      '<input type="email" name="email" value="' +
      esc(edit ? edit.email : '') +
      '">' +
      '</div>' +

      '<div>' +
      '<label>Address</label>' +
      '<input name="address" value="' +
      esc(edit ? edit.address : '') +
      '">' +
      '</div>' +

      '</div><br>' +

      '<div class="actions">' +
      '<button class="btn">' +
      (edit ? 'Update Customer' : 'Add Customer') +
      '</button>' +

      (edit
        ? '<a class="btn secondary" href="/customers">Cancel</a>'
        : '') +

      '</div>' +

      '</form>' +
      '</div>';

    const content =
      form +

      '<div class="panel">' +
      '<h2>Customers</h2>' +

      '<form class="searchbar" method="get">' +
      '<input name="search" placeholder="Search name, phone or email" value="' +
      esc(search) +
      '">' +
      '<button class="btn">Search</button>' +
      '<a class="btn secondary" href="/customers">Clear</a>' +
      '</form>' +

      '<div class="tablewrap">' +
      '<table class="table">' +
      '<thead><tr>' +
      '<th>Name</th>' +
      '<th>Phone</th>' +
      '<th>Email</th>' +
      '<th>Address</th>' +
      '<th>Actions</th>' +
      '</tr></thead>' +

      '<tbody>' +
      (rows ||
        '<tr><td colspan="5" class="empty">No customers found</td></tr>') +
      '</tbody>' +

      '</table>' +
      '</div>' +
      '</div>';

    res.send(page('Customers', content, 'customers'));
  } catch (err) {
    console.error(err);
    res.status(500).send('Customer error: ' + esc(err.message));
  }
});

app.post('/customers/add', requireLogin, async function(req, res) {
  if (!String(req.body.name || '').trim()) {
    return res.status(400).send('Customer name required');
  }

  await pool.query(
    `INSERT INTO customers(name,phone,email,address)
     VALUES($1,$2,$3,$4)`,
    [
      req.body.name,
      req.body.phone,
      req.body.email,
      req.body.address
    ]
  );

  res.redirect('/customers');
});

app.post('/customers/edit/:id', requireLogin, async function(req, res) {
  await pool.query(
    `UPDATE customers
     SET name=$1,phone=$2,email=$3,address=$4
     WHERE id=$5`,
    [
      req.body.name,
      req.body.phone,
      req.body.email,
      req.body.address,
      req.params.id
    ]
  );

  res.redirect('/customers');
});

app.post('/customers/delete/:id', requireLogin, async function(req, res) {
  await pool.query(
    'DELETE FROM customers WHERE id=$1',
    [req.params.id]
  );

  res.redirect('/customers');
});

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

function options(list, value) {
  return list.map(function(x) {
    return '<option value="' +
      esc(x) +
      '" ' +
      selected(x, value) +
      '>' +
      esc(x) +
      '</option>';
  }).join('');
}

app.get('/leads', requireLogin, async function(req, res) {
  try {
    const search = String(req.query.search || '').trim();
    const status = String(req.query.status || '').trim();
    const source = String(req.query.source || '').trim();

    let sql = 'SELECT * FROM leads';
    const vals = [];
    const where = [];

    if (search) {
      vals.push('%' + search + '%');

      where.push(
        '(name ILIKE $' +
        vals.length +
        ' OR phone ILIKE $' +
        vals.length +
        ' OR email ILIKE $' +
        vals.length +
        ')'
      );
    }

    if (status) {
      vals.push(status);
      where.push('status=$' + vals.length);
    }

    if (source) {
      vals.push(source);
      where.push('source=$' + vals.length);
    }

    if (where.length) {
      sql += ' WHERE ' + where.join(' AND ');
    }

    sql += ' ORDER BY id DESC';

    const result = await pool.query(sql, vals);

    const editId = req.query.edit
      ? Number(req.query.edit)
      : 0;

    let edit = null;

    if (editId) {
      const er = await pool.query(
        'SELECT * FROM leads WHERE id=$1',
        [editId]
      );

      edit = er.rows[0] || null;
    }

    const form =
      '<div class="panel">' +
      '<h2>' +
      (edit ? 'Edit Lead' : 'Add Lead') +
      '</h2>' +

      '<form method="post" action="' +
      (edit
        ? '/leads/edit/' + edit.id
        : '/leads/add') +
      '">' +

      '<div class="formgrid three">' +

      '<div>' +
      '<label>Name</label>' +
      '<input name="name" value="' +
      esc(edit ? edit.name : '') +
      '" required>' +
      '</div>' +

      '<div>' +
      '<label>Phone</label>' +
      '<input name="phone" value="' +
      esc(edit ? edit.phone : '') +
      '">' +
      '</div>' +

      '<div>' +
      '<label>Email</label>' +
      '<input type="email" name="email" value="' +
      esc(edit ? edit.email : '') +
      '">' +
      '</div>' +

      '<div>' +
      '<label>Source</label>' +
      '<select name="source">' +
      '<option value="">Select source</option>' +
      options(sourceOptions, edit ? edit.source : '') +
      '</select>' +
      '</div>' +

      '<div>' +
      '<label>Status</label>' +
      '<select name="status">' +
      options(statusOptions, edit ? edit.status : 'New') +
      '</select>' +
      '</div>' +

      '<div>' +
      '<label>Follow-up date</label>' +
      '<input type="date" name="follow_up" value="' +
      esc(edit ? edit.follow_up : '') +
      '">' +
      '</div>' +

      '</div><br>' +

      '<div>' +
      '<label>Notes</label>' +
      '<textarea name="notes" placeholder="Lead notes...">' +
      esc(edit ? edit.notes : '') +
      '</textarea>' +
      '</div>' +

      '<br>' +

      '<div class="actions">' +
      '<button class="btn">' +
      (edit ? 'Update Lead' : 'Save Lead') +
      '</button>' +

      (edit
        ? '<a class="btn secondary" href="/leads">Cancel</a>'
        : '') +

      '</div>' +

      '</form>' +
      '</div>';

    const rows = result.rows.map(function(l) {
      const cls =
        l.status === 'Converted'
          ? 'green'
          : l.status === 'Lost'
          ? 'red'
          : l.status === 'Follow-up'
          ? 'yellow'
          : '';

      return '<tr>' +
        '<td>' + esc(l.name) + '</td>' +
        '<td>' + esc(l.phone) + '</td>' +
        '<td>' + esc(l.source) + '</td>' +
        '<td><span class="pill ' +
        cls +
        '">' +
        esc(l.status) +
        '</span></td>' +
        '<td>' +
        esc(l.follow_up || '-') +
        '</td>' +
        '<td>' +
        esc(l.notes || '-') +
        '</td>' +
        '<td>' +
        '<div class="actions">' +

        '<a class="btn secondary" href="/leads?edit=' +
        l.id +
        '">Edit</a>' +

        '<form method="post" action="/leads/delete/' +
        l.id +
        '" onsubmit="return confirm(\'Delete this lead?\')">' +
        '<button class="btn danger">Delete</button>' +
        '</form>' +

        '</div>' +
        '</td>' +
        '</tr>';
    }).join('');

    const filters =
      '<form class="searchbar" method="get">' +

      '<input name="search" placeholder="Search lead" value="' +
      esc(search) +
      '">' +

      '<select name="source">' +
      '<option value="">All sources</option>' +
      options(sourceOptions, source) +
      '</select>' +

      '<select name="status">' +
      '<option value="">All status</option>' +
      options(statusOptions, status) +
      '</select>' +

      '<button class="btn">Filter</button>' +

      '<a class="btn secondary" href="/leads">Clear</a>' +

      '</form>';

    res.send(
      page(
        'Leads',
        form +
        '<div class="panel">' +
        '<h2>Lead Management</h2>' +
        filters +
        '<div class="tablewrap">' +
        '<table class="table">' +

        '<thead><tr>' +
        '<th>Name</th>' +
        '<th>Phone</th>' +
        '<th>Source</th>' +
        '<th>Status</th>' +
        '<th>Follow-up</th>' +
        '<th>Notes</th>' +
        '<th>Actions</th>' +
        '</tr></thead>' +

        '<tbody>' +
        (rows ||
          '<tr><td colspan="7" class="empty">No leads found</td></tr>') +
        '</tbody>' +

        '</table>' +
        '</div>' +
        '</div>',
        'leads'
      )
    );
  } catch (err) {
    console.error(err);
    res.status(500).send('Lead error: ' + esc(err.message));
  }
});

app.post('/leads/add', requireLogin, async function(req, res) {
  if (!String(req.body.name || '').trim()) {
    return res.status(400).send('Lead name required');
  }

  await pool.query(
    `INSERT INTO leads
     (name,phone,email,source,status,follow_up,notes)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [
      req.body.name,
      req.body.phone,
      req.body.email,
      req.body.source,
      req.body.status || 'New',
      req.body.follow_up || null,
      req.body.notes
    ]
  );

  res.redirect('/leads');
});

app.post('/leads/edit/:id', requireLogin, async function(req, res) {
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
      req.body.name,
      req.body.phone,
      req.body.email,
      req.body.source,
      req.body.status,
      req.body.follow_up || null,
      req.body.notes,
      req.params.id
    ]
  );

  res.redirect('/leads');
});

app.post('/leads/delete/:id', requireLogin, async function(req, res) {
  await pool.query(
    'DELETE FROM leads WHERE id=$1',
    [req.params.id]
  );

  res.redirect('/leads');
});

app.get('/followups', requireLogin, async function(req, res) {
  const result = await pool.query(
    `SELECT * FROM leads
     WHERE follow_up IS NOT NULL
     ORDER BY follow_up ASC, id DESC`
  );

  const today =
    new Date().toISOString().slice(0, 10);

  const rows = result.rows.map(function(l) {
    const overdue =
      String(l.follow_up).slice(0, 10) < today &&
      !['Converted', 'Lost'].includes(l.status);

    return '<tr>' +
      '<td>' + esc(l.name) + '</td>' +
      '<td>' + esc(l.phone) + '</td>' +
      '<td>' + esc(l.follow_up) + '</td>' +
      '<td><span class="pill ' +
      (overdue ? 'red' : 'yellow') +
      '">' +
      (overdue ? 'Overdue' : 'Scheduled') +
      '</span></td>' +
      '<td>' + esc(l.status) + '</td>' +
      '<td><a class="btn secondary" href="/leads?edit=' +
      l.id +
      '">Open Lead</a></td>' +
      '</tr>';
  }).join('');

  res.send(
    page(
      'Follow-ups',
      '<div class="panel">' +
      '<h2>Follow-up Schedule</h2>' +
      '<p class="muted">Track scheduled and overdue lead follow-ups.</p>' +
      '<div class="tablewrap">' +
      '<table class="table">' +
      '<thead><tr>' +
      '<th>Lead</th>' +
      '<th>Phone</th>' +
      '<th>Date</th>' +
      '<th>State</th>' +
      '<th>Status</th>' +
      '<th>Action</th>' +
      '</tr></thead>' +
      '<tbody>' +
      (rows ||
        '<tr><td colspan="6" class="empty">No follow-ups yet</td></tr>') +
      '</tbody>' +
      '</table>' +
      '</div>' +
      '</div>',
      'followups'
    )
  );
});

app.get('/staff', requireLogin, async function(req, res) {
  const result = await pool.query(
    'SELECT id,username,role,created_at FROM users ORDER BY id'
  );

  const rows = result.rows.map(function(u) {
    return '<tr>' +
      '<td>' + esc(u.username) + '</td>' +
      '<td>' + esc(u.role) + '</td>' +
      '<td>' + esc(u.created_at) + '</td>' +
      '</tr>';
  }).join('');

  res.send(
    page(
      'Staff',
      '<div class="grid2">' +

      '<div class="panel">' +
      '<h2>Add Staff</h2>' +
      '<form method="post" action="/staff/add">' +

      '<div class="formgrid">' +

      '<div>' +
      '<label>Username</label>' +
      '<input name="username" required>' +
      '</div>' +

      '<div>' +
      '<label>Password</label>' +
      '<input name="password" type="password" required>' +
      '</div>' +

      '</div><br>' +

      '<button class="btn">Add Staff</button>' +

      '</form>' +
      '</div>' +

      '<div class="panel">' +
      '<h2>Team</h2>' +
      '<div class="tablewrap">' +
      '<table class="table">' +
      '<thead><tr>' +
      '<th>Username</th>' +
      '<th>Role</th>' +
      '<th>Created</th>' +
      '</tr></thead>' +
      '<tbody>' +
      rows +
      '</tbody>' +
      '</table>' +
      '</div>' +
      '</div>' +

      '</div>',
      'staff'
    )
  );
});

app.post('/staff/add', requireLogin, async function(req, res) {
  if (!req.body.username || !req.body.password) {
    return res.status(400).send(
      'Username and password required'
    );
  }

  await pool.query(
    'INSERT INTO users(username,password,role) VALUES($1,$2,$3)',
    [
      req.body.username,
      req.body.password,
      'staff'
    ]
  );

  res.redirect('/staff');
});

app.get('/api-info', requireLogin, function(req, res) {
  const content =
    '<div class="panel">' +
    '<h2>CRM API</h2>' +
    '<p class="muted">' +
    'Use these endpoints later for website, ads and WhatsApp integrations.' +
    '</p>' +

    '<div class="notice">' +
    '<b>GET /api/customers</b><br>' +
    'Returns customers.' +
    '</div>' +

    '<div class="notice">' +
    '<b>GET /api/leads</b><br>' +
    'Returns leads.' +
    '</div>' +

    '<div class="notice">' +
    '<b>POST /api/leads</b><br>' +
    'Creates a new lead using JSON.' +
    '</div>' +

    '<div class="notice">' +
    '<b>GET /health</b><br>' +
    'Checks API status.' +
    '</div>' +

    '</div>';

  res.send(page('API', content, 'api'));
});

app.get('/api/customers', async function(req, res) {
  try {
    const r =
      await pool.query(
        'SELECT * FROM customers ORDER BY id DESC'
      );

    res.json(r.rows);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

app.get('/api/leads', async function(req, res) {
  try {
    const r =
      await pool.query(
        'SELECT * FROM leads ORDER BY id DESC'
      );

    res.json(r.rows);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

app.post('/api/leads', async function(req, res) {
  try {
    if (!req.body.name) {
      return res.status(400).json({
        error: 'name is required'
      });
    }

    const r = await pool.query(
      `INSERT INTO leads
       (name,phone,email,source,status,follow_up,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        req.body.name,
        req.body.phone || '',
        req.body.email || '',
        req.body.source || 'API',
        req.body.status || 'New',
        req.body.follow_up || null,
        req.body.notes || ''
      ]
    );

    res.status(201).json(r.rows[0]);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

app.get('/health', function(req, res) {
  res.json({
    status: 'ok',
    service: 'CRM API'
  });
});

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