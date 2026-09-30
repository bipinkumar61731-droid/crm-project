const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "crm-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

// ================= DATABASE =================

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      source TEXT DEFAULT 'Other',
      status TEXT DEFAULT 'New',
      follow_up_date DATE,
      notes TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const admin = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["admin"]
  );

  if (admin.rowCount === 0) {
    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      ["admin", "Admin@123"]
    );
  }
}

// ================= LOGIN =================

function requireLogin(req, res, next) {
  if (req.session.user) {
    return next();
  }

  if (
    req.path === "/customers" ||
    req.path.startsWith("/customers/") ||
    req.path === "/leads" ||
    req.path.startsWith("/leads/")
  ) {
    return res.status(401).json({
      error: "Please login first"
    });
  }

  return res.redirect("/login");
}

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CRM Login</title>
<style>
body{
  font-family:Arial;
  background:#f3f4f6;
  display:flex;
  justify-content:center;
  align-items:center;
  min-height:100vh;
  margin:0;
}
.box{
  background:white;
  padding:25px;
  width:320px;
  border-radius:12px;
  box-shadow:0 5px 20px #ccc;
}
input,button{
  width:100%;
  padding:12px;
  margin:7px 0;
  box-sizing:border-box;
  border-radius:7px;
  border:1px solid #ccc;
}
button{
  background:#2563eb;
  color:white;
  border:0;
  cursor:pointer;
}
#error{
  color:red;
}
</style>
</head>

<body>

<div class="box">
<h2>CRM Login</h2>

<div id="error"></div>

<input id="username" placeholder="Username">
<input id="password" type="password" placeholder="Password">

<button onclick="login()">Login</button>
</div>

<script>

async function login(){

  const username =
    document.getElementById("username").value.trim();

  const password =
    document.getElementById("password").value;

  if(!username || !password){
    document.getElementById("error").textContent =
      "Username and password required";
    return;
  }

  try{

    const response = await fetch("/login",{
      method:"POST",
      headers:{
        "Content-Type":"application/json"
      },
      body:JSON.stringify({
        username,
        password
      })
    });

    const data = await response.json();

    if(!response.ok){
      document.getElementById("error").textContent =
        data.error || "Login failed";
      return;
    }

    window.location.href="/";

  }catch(error){

    console.error(error);

    document.getElementById("error").textContent =
      "Server error";

  }
}

</script>

</body>
</html>
`);
});

app.post("/login", async (req, res) => {
  try {

    const { username, password } = req.body;

    const result = await pool.query(
      `SELECT id, username
       FROM users
       WHERE username = $1
       AND password = $2`,
      [username, password]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    req.session.user = {
      id: result.rows[0].id,
      username: result.rows[0].username
    };

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Login error"
    });

  }
});

app.post("/logout", requireLogin, (req, res) => {

  req.session.destroy(() => {

    res.json({
      success: true
    });

  });

});

// ================= CUSTOMER API =================

app.get("/customers", requireLogin, async (req, res) => {

  try {

    const result = await pool.query(
      "SELECT * FROM customers ORDER BY id DESC"
    );

    res.json(result.rows);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.post("/customers", requireLogin, async (req, res) => {

  try {

    const {
      name,
      phone,
      email,
      address
    } = req.body;

    if (!name || !name.trim()) {

      return res.status(400).json({
        error:"Customer name required"
      });

    }

    const result = await pool.query(
      `INSERT INTO customers
      (name,phone,email,address)
      VALUES ($1,$2,$3,$4)
      RETURNING *`,
      [
        name.trim(),
        phone || "",
        email || "",
        address || ""
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch(error) {

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.put("/customers/:id", requireLogin, async (req,res) => {

  try {

    const {
      name,
      phone,
      email,
      address
    } = req.body;

    if(!name || !name.trim()){

      return res.status(400).json({
        error:"Customer name required"
      });

    }

    const result = await pool.query(
      `UPDATE customers
       SET name=$1,
           phone=$2,
           email=$3,
           address=$4
       WHERE id=$5
       RETURNING *`,
      [
        name.trim(),
        phone || "",
        email || "",
        address || "",
        req.params.id
      ]
    );

    if(result.rowCount === 0){

      return res.status(404).json({
        error:"Customer not found"
      });

    }

    res.json(result.rows[0]);

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.delete("/customers/:id", requireLogin, async (req,res) => {

  try {

    const result = await pool.query(
      "DELETE FROM customers WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if(result.rowCount === 0){

      return res.status(404).json({
        error:"Customer not found"
      });

    }

    res.json({
      success:true
    });

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

// ================= LEAD API =================

app.get("/leads", requireLogin, async (req,res) => {

  try {

    const result = await pool.query(
      "SELECT * FROM leads ORDER BY id DESC"
    );

    res.json(result.rows);

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.post("/leads", requireLogin, async (req,res) => {

  try {

    const {
      name,
      phone,
      email,
      source,
      status,
      follow_up_date,
      notes
    } = req.body;

    if(!name || !name.trim()){

      return res.status(400).json({
        error:"Lead name required"
      });

    }

    const result = await pool.query(
      `INSERT INTO leads
      (name,phone,email,source,status,follow_up_date,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *`,
      [
        name.trim(),
        phone || "",
        email || "",
        source || "Other",
        status || "New",
        follow_up_date || null,
        notes || ""
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.put("/leads/:id", requireLogin, async (req,res) => {

  try {

    const {
      name,
      phone,
      email,
      source,
      status,
      follow_up_date,
      notes
    } = req.body;

    if(!name || !name.trim()){

      return res.status(400).json({
        error:"Lead name required"
      });

    }

    const result = await pool.query(
      `UPDATE leads
       SET name=$1,
           phone=$2,
           email=$3,
           source=$4,
           status=$5,
           follow_up_date=$6,
           notes=$7
       WHERE id=$8
       RETURNING *`,
      [
        name.trim(),
        phone || "",
        email || "",
        source || "Other",
        status || "New",
        follow_up_date || null,
        notes || "",
        req.params.id
      ]
    );

    if(result.rowCount === 0){

      return res.status(404).json({
        error:"Lead not found"
      });

    }

    res.json(result.rows[0]);

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

app.delete("/leads/:id", requireLogin, async (req,res) => {

  try {

    const result = await pool.query(
      "DELETE FROM leads WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if(result.rowCount === 0){

      return res.status(404).json({
        error:"Lead not found"
      });

    }

    res.json({
      success:true
    });

  } catch(error){

    console.error(error);

    res.status(500).json({
      error:"Database error"
    });

  }

});

// ================= DASHBOARD =================

app.get("/", requireLogin, (req,res) => {

res.send(`

<!DOCTYPE html>

<html>

<head>

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>CRM Dashboard</title>

<style>

body{
font-family:Arial;
background:#f4f6f8;
margin:0;
color:#111827;
}

header{
background:#111827;
color:white;
padding:16px;
display:flex;
justify-content:space-between;
align-items:center;
}

.container{
max-width:1100px;
margin:auto;
padding:20px;
}

.grid{
display:grid;
grid-template-columns:
repeat(auto-fit,minmax(320px,1fr));
gap:20px;
}

.box{
background:white;
padding:18px;
margin-bottom:20px;
border-radius:12px;
box-shadow:0 3px 15px #ddd;
}

input,
select,
textarea{
width:100%;
box-sizing:border-box;
padding:11px;
margin:6px 0 10px;
border:1px solid #ccc;
border-radius:7px;
font-size:15px;
}

textarea{
min-height:80px;
}

button{
padding:10px 15px;
border:0;
border-radius:7px;
cursor:pointer;
}

.primary{
background:#2563eb;
color:white;
}

.danger{
background:#dc2626;
color:white;
}

.edit{
background:#e5e7eb;
}

.item{
border:1px solid #ddd;
padding:12px;
margin:10px 0;
border-radius:8px;
background:#fafafa;
}

.actions{
display:flex;
gap:8px;
margin-top:10px;
}

.stats{
display:grid;
grid-template-columns:
repeat(3,1fr);
gap:12px;
margin-bottom:20px;
}

.stat{
background:white;
padding:15px;
border-radius:10px;
box-shadow:0 2px 10px #ddd;
}

.stat strong{
display:block;
font-size:28px;
margin-top:5px;
}

@media(max-width:600px){

.container{
padding:12px;
}

.stats{
grid-template-columns:1fr;
}

}

</style>

</head>

<body>

<header>

<h2>CRM Dashboard</h2>

<button
class="danger"
onclick="logout()">
Logout
</button>

</header>

<div class="container">

<div class="stats">

<div class="stat">
Customers
<strong id="customer-count">0</strong>
</div>

<div class="stat">
Leads
<strong id="lead-count">0</strong>
</div>

<div class="stat">
Converted
<strong id="converted-count">0</strong>
</div>

</div>

<div class="grid">

<!-- CUSTOMER -->

<div class="box">

<h2>➕ Add Customer</h2>

<input
id="customer-name"
placeholder="Customer Name">

<input
id="customer-phone"
placeholder="Phone Number">

<input
id="customer-email"
placeholder="Email">

<input
id="customer-address"
placeholder="Address">

<button
class="primary"
onclick="addCustomer()">

Add Customer

</button>

</div>


<!-- LEAD -->

<div class="box">

<h2>➕ Add Lead</h2>

<input
id="lead-name"
placeholder="Lead Name">

<input
id="lead-phone"
placeholder="Phone Number">

<input
id="lead-email"
placeholder="Email">

<select id="lead-source">

<option value="Other">
Source - Other
</option>

<option value="Website">
Website
</option>

<option value="WhatsApp">
WhatsApp
</option>

<option value="Facebook Ads">
Facebook Ads
</option>

<option value="Instagram">
Instagram
</option>

<option value="Google Ads">
Google Ads
</option>

<option value="Referral">
Referral
</option>

</select>

<select id="lead-status">

<option value="New">
New
</option>

<option value="Contacted">
Contacted
</option>

<option value="Interested">
Interested
</option>

<option value="Converted">
Converted
</option>

<option value="Lost">
Lost
</option>

</select>

<input
id="lead-follow-up"
type="date">

<textarea
id="lead-notes"
placeholder="Notes">
</textarea>

<button
class="primary"
onclick="addLead()">

Add Lead

</button>

</div>

</div>


<!-- CUSTOMER LIST -->

<div class="box">

<h2>👥 Customers</h2>

<input
id="customer-search"
placeholder="Search customer..."
oninput="renderCustomers()">

<div id="customer-list">
Loading...
</div>

</div>


<!-- LEAD LIST -->

<div class="box">

<h2>🎯 Customer Leads</h2>

<input
id="lead-search"
placeholder="Search lead..."
oninput="renderLeads()">

<div id="lead-list">
Loading...
</div>

</div>

</div>


<script>

let customers = [];
let leads = [];


function escapeHtml(value){

return String(value || "")
.replace(/&/g,"&amp;")
.replace(/</g,"&lt;")
.replace(/>/g,"&gt;")
.replace(/"/g,"&quot;")
.replace(/'/g,"&#039;");

}


async function api(url,options={}){

const response =
await fetch(url,options);

if(response.status===401){

window.location.href="/login";

throw new Error("Login required");

}

let data={};

try{

data=await response.json();

}catch(e){}

if(!response.ok){

throw new Error(
data.error || "Request failed"
);

}

return data;

}


// ================= CUSTOMER =================

async function loadCustomers(){

try{

customers =
await api("/customers");

renderCustomers();

updateStats();

}catch(error){

console.error(error);

document.getElementById(
"customer-list"
).innerHTML =
"<p>Customers load nahi ho pa rahe.</p>";

}

}


function renderCustomers(){

const list =
document.getElementById(
"customer-list"
);

const search =
document.getElementById(
"customer-search"
).value
.toLowerCase()
.trim();

const filtered =
customers.filter(c =>

String(c.name || "")
.toLowerCase()
.includes(search)

||

String(c.phone || "")
.toLowerCase()
.includes(search)

||

String(c.email || "")
.toLowerCase()
.includes(search)

);

if(filtered.length===0){

list.innerHTML =
"<p>No customers found.</p>";

return;

}

list.innerHTML =
filtered.map(c => `

<div class="item">

<b>${escapeHtml(c.name)}</b>

<br>

Phone:
${escapeHtml(c.phone || "-")}

<br>

Email:
${escapeHtml(c.email || "-")}

<br>

Address:
${escapeHtml(c.address || "-")}

<div class="actions">

<button
class="edit"
onclick="editCustomer(${c.id})">

Edit

</button>

<button
class="danger"
onclick="deleteCustomer(${c.id})">

Delete

</button>

</div>

</div>

`).join("");

}


async function addCustomer(){

const name =
document.getElementById(
"customer-name"
).value.trim();

const phone =
document.getElementById(
"customer-phone"
).value.trim();

const email =
document.getElementById(
"customer-email"
).value.trim();

const address =
document.getElementById(
"customer-address"
).value.trim();


if(!name){

alert("Customer name required");

return;

}


try{

await api("/customers",{

method:"POST",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({

name,
phone,
email,
address

})

});


alert(
"Customer added successfully!"
);


document.getElementById(
"customer-name"
).value="";

document.getElementById(
"customer-phone"
).value="";

document.getElementById(
"customer-email"
).value="";

document.getElementById(
"customer-address"
).value="";


await loadCustomers();


}catch(error){

console.error(error);

alert(
error.message ||
"Customer add error"
);

}

}


async function editCustomer(id){

const customer =
customers.find(
c => Number(c.id)===Number(id)
);

if(!customer){

alert("Customer not found");

return;

}


const name =
prompt(
"Customer Name",
customer.name || ""
);

if(name===null)return;


const phone =
prompt(
"Phone Number",
customer.phone || ""
);

if(phone===null)return;


const email =
prompt(
"Email",
customer.email || ""
);

if(email===null)return;


const address =
prompt(
"Address",
customer.address || ""
);

if(address===null)return;


try{

await api(
"/customers/"+id,
{

method:"PUT",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({

name:name.trim(),
phone,
email,
address

})

});


alert(
"Customer updated successfully!"
);


await loadCustomers();


}catch(error){

alert(
error.message ||
"Customer update error"
);

}

}


async function deleteCustomer(id){

if(!confirm(
"Delete this customer?"
))return;


try{

await api(
"/customers/"+id,
{
method:"DELETE"
}
);


alert(
"Customer deleted successfully!"
);


await loadCustomers();


}catch(error){

alert(
error.message ||
"Customer delete error"
);

}

}


// ================= LEADS =================

async function loadLeads(){

try{

leads =
await api("/leads");

renderLeads();

updateStats();

}catch(error){

console.error(error);

document.getElementById(
"lead-list"
).innerHTML =
"<p>Leads load nahi ho pa rahe.</p>";

}

}


function renderLeads(){

const list =
document.getElementById(
"lead-list"
);

const search =
document.getElementById(
"lead-search"
).value
.toLowerCase()
.trim();


const filtered =
leads.filter(l =>

String(l.name || "")
.toLowerCase()
.includes(search)

||

String(l.phone || "")
.toLowerCase()
.includes(search)

||

String(l.email || "")
.toLowerCase()
.includes(search)

||

String(l.source || "")
.toLowerCase()
.includes(search)

||

String(l.status || "")
.toLowerCase()
.includes(search)

);


if(filtered.length===0){

list.innerHTML =
"<p>No leads found.</p>";

return;

}


list.innerHTML =
filtered.map(l => `

<div class="item">

<b>${escapeHtml(l.name)}</b>

<br>

Phone:
${escapeHtml(l.phone || "-")}

<br>

Email:
${escapeHtml(l.email || "-")}

<br>

Source:
${escapeHtml(l.source || "-")}

<br>

Status:
${escapeHtml(l.status || "-")}

<br>

Follow-up:
${escapeHtml(l.follow_up_date || "-")}

<br>

Notes:
${escapeHtml(l.notes || "-")}

<div class="actions">

<button
class="edit"
onclick="editLead(${l.id})">

Edit

</button>

<button
class="danger"
onclick="deleteLead(${l.id})">

Delete

</button>

</div>

</div>

`).join("");

}


async function addLead(){

const name =
document.getElementById(
"lead-name"
).value.trim();

const phone =
document.getElementById(
"lead-phone"
).value.trim();

const email =
document.getElementById(
"lead-email"
).value.trim();

const source =
document.getElementById(
"lead-source"
).value;

const status =
document.getElementById(
"lead-status"
).value;

const follow_up_date =
document.getElementById(
"lead-follow-up"
).value;

const notes =
document.getElementById(
"lead-notes"
).value.trim();


if(!name){

alert("Lead name required");

return;

}


try{

await api("/leads",{

method:"POST",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({

name,
phone,
email,
source,
status,
follow_up_date,