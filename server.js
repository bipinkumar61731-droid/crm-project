const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "crm-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);

// -------------------------
// Database setup
// -------------------------

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
      password TEXT NOT NULL
    )
  `);

  const existingAdmin = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["admin"]
  );

  if (existingAdmin.rows.length === 0) {
    const passwordHash = await bcrypt.hash("Admin@123", 10);

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      ["admin", passwordHash]
    );

    console.log("Admin user created.");
  }

  console.log("PostgreSQL database ready.");
}

// -------------------------
// Login protection
// -------------------------

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please login first"
    });
  }

  next();
}

// -------------------------
// Login page
// -------------------------

app.get("/login", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>CRM Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f2f4f7;
      margin: 0;
      padding: 20px;
    }

    .login-box {
      max-width: 400px;
      margin: 80px auto;
      background: white;
      padding: 25px;
      border-radius: 12px;
      box-shadow: 0 2px 12px #ddd;
    }

    input {
      width: 100%;
      padding: 12px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 6px;
    }

    button {
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 6px;
      background: #2563eb;
      color: white;
      cursor: pointer;
      margin-top: 10px;
    }
  </style>
</head>

<body>

<div class="login-box">
  <h2>🔐 CRM Login</h2>

  <form method="POST" action="/login">
    <input
      name="username"
      placeholder="Username"
      required
    >

    <input
      name="password"
      type="password"
      placeholder="Password"
      required
    >

    <button type="submit">Login</button>
  </form>
</div>

</body>
</html>
  `);
});

// -------------------------
// Login
// -------------------------

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).send("Invalid username or password");
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).send("Invalid username or password");
    }

    req.session.userId = user.id;

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Login error");
  }
});

// -------------------------
// Logout
// -------------------------

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// -------------------------
// Dashboard
// -------------------------

app.get("/", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>My CRM</title>

  <meta name="viewport" content="width=device-width, initial-scale=1">

  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f2f4f7;
      margin: 0;
      padding: 20px;
    }

    .container {
      max-width: 900px;
      margin: auto;
    }

    h1 {
      background: #111827;
      color: white;
      padding: 20px;
      border-radius: 10px;
    }

    .box {
      background: white;
      padding: 20px;
      margin-top: 20px;
      border-radius: 10px;
      box-shadow: 0 2px 8px #ddd;
    }

    input {
      width: 100%;
      padding: 12px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 6px;
    }

    button {
      padding: 12px 18px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      background: #2563eb;
      color: white;
      margin-top: 8px;
    }

    .delete {
      background: #dc2626;
      margin-left: 8px;
    }

    .logout {
      background: #6b7280;
      float: right;
    }

    .customer {
      border: 1px solid #ddd;
      padding: 15px;
      margin-top: 10px;
      border-radius: 8px;
    }

    .search {
      margin-top: 20px;
    }
  </style>
</head>

<body>

<div class="container">

  <h1>
    📊 My CRM Dashboard
    <button class="logout" onclick="logout()">Logout</button>
  </h1>

  <div class="box">
    <h2>➕ Add Customer / Lead</h2>

    <input id="name" placeholder="Customer Name">
    <input id="phone" placeholder="Phone Number">
    <input id="email" placeholder="Email">
    <input id="address" placeholder="Address">

    <button onclick="addCustomer()">Add Customer</button>
  </div>

  <div class="box">
<div class="box">
  <h2>➕ Add Lead</h2>

  <input id="lead-name" placeholder="Lead Name">
  <input id="lead-phone" placeholder="Phone Number">
  <input id="lead-email" placeholder="Email">
  
  <select id="lead-source">
    <option value="Other">Source - Other</option>
    <option value="Website">Website</option>
    <option value="WhatsApp">WhatsApp</option>
    <option value="Facebook Ads">Facebook Ads</option>
    <option value="Instagram">Instagram</option>
    <option value="Google Ads">Google Ads</option>
    <option value="Referral">Referral</option>
  </select>

  <select id="lead-status">
    <option value="New">New</option>
    <option value="Contacted">Contacted</option>
    <option value="Interested">Interested</option>
    <option value="Converted">Converted</option>
    <option value="Lost">Lost</option>
  </select>

  <input id="lead-follow-up" type="date">

  <textarea id="lead-notes" placeholder="Notes"></textarea>

  <button onclick="addLead()">Add Lead</button>
</div>
    <h2>👥 Customers / Leads</h2>

    <input
      class="search"
      id="search"
      placeholder="🔍 Search customer..."
      oninput="loadCustomers()"
    >

    <div id="customers"></div>
  </div>

</div>

<script>

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function addCustomer() {

  const name = document.getElementById("name").value.trim();
  const phone = document.getElementById("phone").value.trim();
  const email = document.getElementById("email").value.trim();
  const address = document.getElementById("address").value.trim();

  if (!name) {
    alert("Customer name required");
    return;
  }

  const response = await fetch("/customers", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name,
      phone,
      email,
      address
    })
  });

  if (response.ok) {

    document.getElementById("name").value = "";
    document.getElementById("phone").value = "";
    document.getElementById("email").value = "";
    document.getElementById("address").value = "";

    await loadCustomers();

    alert("Customer added successfully!");
  } else {
    alert("Customer add nahi hua");
  }
}
async function addLead() {
  const name = document.getElementById("lead-name").value.trim();
  const phone = document.getElementById("lead-phone").value.trim();
  const email = document.getElementById("lead-email").value.trim();
  const source = document.getElementById("lead-source").value;
  const status = document.getElementById("lead-status").value;
  const follow_up_date = document.getElementById("lead-follow-up").value;
  const notes = document.getElementById("lead-notes").value.trim();

  if (!name) {
    alert("Lead name required");
    return;
  }

  const response = await fetch("/leads", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name,
      phone,
      email,
      source,
      status,
      follow_up_date,
      notes
    })
  });

  const data = await response.json();

  if (!response.ok) {
    alert(data.error || "Failed to add lead");
    return;
  }

  alert("Lead added successfully!");

  document.getElementById("lead-name").value = "";
  document.getElementById("lead-phone").value = "";
  document.getElementById("lead-email").value = "";
  document.getElementById("lead-source").value = "Other";
  document.getElementById("lead-status").value = "New";
  document.getElementById("lead-follow-up").value = "";
  document.getElementById("lead-notes").value = "";
}
async function loadCustomers() {

  const response = await fetch("/customers");

  if (!response.ok) {
    document.getElementById("customers").innerHTML =
      "<p>Unable to load customers.</p>";
    return;
  }

  const customers = await response.json();

  const search =
    document.getElementById("search").value.toLowerCase();

  const container =
    document.getElementById("customers");

  container.innerHTML = "";

  const filtered = customers.filter(function(customer) {

    return (
      (customer.name || "").toLowerCase().includes(search) ||
      (customer.phone || "").includes(search) ||
      (customer.email || "").toLowerCase().includes(search)
    );

  });

  if (filtered.length === 0) {
    container.innerHTML = "<p>No customers found.</p>";
    return;
  }

  filtered.forEach(function(customer) {

    const div = document.createElement("div");

    div.className = "customer";

    div.innerHTML =
      "<strong>" +
      escapeHtml(customer.name) +
      "</strong><br>" +

      "📞 " +
      escapeHtml(customer.phone) +
      "<br>" +

      "📧 " +
      escapeHtml(customer.email) +
      "<br>" +

      "📍 " +
      escapeHtml(customer.address) +

      "<br>" +

      "<button onclick='editCustomer(" +
      customer.id +
      ")'>✏️ Edit</button>" +

      "<button class='delete' onclick='deleteCustomer(" +
      customer.id +
      ")'>🗑 Delete</button>";

    container.appendChild(div);
  });
}

async function editCustomer(id) {

  const response =
    await fetch("/customers/" + id);

  if (!response.ok) {
    alert("Customer not found");
    return;
  }

  const customer =
    await response.json();

  const name =
    prompt("Customer Name:", customer.name);

  if (name === null) return;

  const phone =
    prompt("Phone:", customer.phone);

  if (phone === null) return;

  const email =
    prompt("Email:", customer.email);

  if (email === null) return;

  const address =
    prompt("Address:", customer.address);

  if (address === null) return;

  const updateResponse =
    await fetch("/customers/" + id, {
      method: "PUT",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        name,
        phone,
        email,
        address
      })
    });

  if (updateResponse.ok) {

    await loadCustomers();

    alert("Customer updated successfully!");

  } else {

    alert("Customer update nahi hua");

  }
}

async function deleteCustomer(id) {

  if (!confirm("Delete this customer?")) {
    return;
  }

  const response =
    await fetch("/customers/" + id, {
      method: "DELETE"
    });

  if (response.ok) {

    await loadCustomers();

  } else {

    alert("Customer delete nahi hua");

  }
}

async function logout() {

  await fetch("/logout", {
    method: "POST"
  });

  window.location.href = "/login";
}

loadCustomers();

</script>

</body>
</html>
  `);
});

// -------------------------
// Get customers
// -------------------------

app.get("/customers", requireLogin, async (req, res) => {

  try {

    const result = await pool.query(
      "SELECT * FROM customers ORDER BY id DESC"
    );

    res.json(result.rows);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Database error"
    });

  }

});

// -------------------------
// Get single customer
// -------------------------

app.get("/customers/:id", requireLogin, async (req, res) => {

  try {

    const id = Number(req.params.id);

    const result = await pool.query(
      "SELECT * FROM customers WHERE id = $1",
      [id]
    );

    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "Customer not found"
      });

    }

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Database error"
    });

  }

});
// ------------------------------
// Get leads
// ------------------------------

app.get("/leads", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM leads ORDER BY id DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Database error"
    });
  }
});

// ------------------------------
// Add lead
// ------------------------------

app.post("/leads", requireLogin, async (req, res) => {
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

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Lead name required"
      });
    }

    const result = await pool.query(
      `INSERT INTO leads
       (name, phone, email, source, status, follow_up_date, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Database error"
    });
  }
});
// -------------------------
// Add customer
// -------------------------

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
        error: "Name is required"
      });

    }

    const result = await pool.query(
      `
      INSERT INTO customers
      (name, phone, email, address)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        name.trim(),
        phone || "",
        email || "",
        address || ""
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Database error"
    });

  }

});

// -------------------------
// Edit customer
// -------------------------

app.put("/customers/:id", requireLogin, async (req, res) => {

  try {

    const id = Number(req.params.id);

    const {
      name,
      phone,
      email,
      address
    } = req.body;

    if (!name || !name.trim()) {

      return res.status(400).json({
        error: "Name is required"
      });

    }

    const result = await pool.query(
      `
      UPDATE customers
      SET
        name = $1,
        phone = $2,
        email = $3,
        address = $4
      WHERE id = $5
      RETURNING *
      `,
      [
        name.trim(),
        phone || "",
        email || "",
        address || "",
        id
      ]
    );

    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "Customer not found"
      });

    }

    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Database error"
    });

  }

});

// -------------------------
// Delete customer
// -------------------------

app.delete("/customers/:id", requireLogin, async (req, res) => {

  try {

    const id = Number(req.params.id);

    const result = await pool.query(
      "DELETE FROM customers WHERE id = $1 RETURNING id",
      [id]
    );

    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "Customer not found"
      });

    }

    res.json({
      message: "Customer deleted successfully"
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Database error"
    });

  }

});

// -------------------------
// Start server
// -------------------------

async function startServer() {

  try {

    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {

      console.log(
        "CRM running on port " + PORT
      );

    });

  } catch (error) {

    console.error(
      "Failed to start CRM:",
      error
    );

    process.exit(1);
  }
}

startServer();