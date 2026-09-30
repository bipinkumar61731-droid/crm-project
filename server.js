const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "crm-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function selected(value, current) {
  return value === current ? "selected" : "";
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function page(title, content) {
  return (
    "<!DOCTYPE html>" +
    "<html>" +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>" +
    escapeHtml(title) +
    "</title>" +
    "<style>" +
    "*{box-sizing:border-box}" +
    "body{margin:0;font-family:Arial,sans-serif;background:#f4f6f8;color:#222}" +
    ".navbar{background:#111827;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}" +
    ".navbar h2{margin:0}" +
    ".navbar a{color:white;text-decoration:none;margin-left:15px}" +
    ".container{max-width:1200px;margin:25px auto;padding:0 15px}" +
    ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin-bottom:25px}" +
    ".card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.08)}" +
    ".card h3{margin:0 0 10px}" +
    ".number{font-size:30px;font-weight:bold}" +
    ".section{background:white;padding:20px;margin-bottom:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.06)}" +
    "input,select,textarea{width:100%;padding:11px;margin:7px 0;border:1px solid #ccc;border-radius:7px;font-size:15px}" +
    "textarea{min-height:90px;resize:vertical}" +
    "button{border:0;padding:10px 16px;border-radius:7px;cursor:pointer;background:#2563eb;color:white;font-size:14px}" +
    ".danger{background:#dc2626}.edit{background:#f59e0b}.green{background:#16a34a}" +
    ".actions{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}" +
    ".item{border:1px solid #ddd;padding:15px;border-radius:10px;margin-top:10px;background:#fafafa}" +
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}" +
    ".login{max-width:400px;margin:80px auto}" +
    ".small{color:#666;font-size:13px}" +
    ".search{margin-bottom:15px}" +
    "</style>" +
    "</head>" +
    "<body>" +
    content +
    "</body>" +
    "</html>"
  );
}

/* DATABASE */

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
    "SELECT id FROM users WHERE username=$1",
    ["admin"]
  );

  if (admin.rows.length === 0) {
    await pool.query(
      "INSERT INTO users(username,password) VALUES($1,$2)",
      ["admin", "Admin@123"]
    );
  }
}

/* LOGIN */

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/");
  }

  const content =
    '<div class="login section">' +
    "<h2>CRM Login</h2>" +
    '<form method="POST" action="/login">' +
    '<input name="username" placeholder="Username" required>' +
    '<input type="password" name="password" placeholder="Password" required>' +
    '<button type="submit">Login</button>' +
    "</form>" +
    '<p class="small">CRM Admin Login</p>' +
    "</div>";

  res.send(page("CRM Login", content));
});

app.post("/login", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1 AND password=$2",
      [req.body.username, req.body.password]
    );

    if (result.rows.length === 0) {
      return res.send(
        page(
          "Login Failed",
          '<div class="login section"><h2>Login Failed</h2><p>Username or password is incorrect.</p><a href="/login">Back to Login</a></div>'
        )
      );
    }

    req.session.user = {
      id: result.rows[0].id,
      username: result.rows[0].username
    };

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Login error");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

/* DASHBOARD */

app.get("/", requireLogin, async (req, res) => {
  try {
    const customers = await pool.query(
      "SELECT * FROM customers ORDER BY id DESC"
    );

    const leads = await pool.query(
      "SELECT * FROM leads ORDER BY id DESC"
    );

    const newLeads = leads.rows.filter(
      function (l) {
        return l.status === "New";
      }
    ).length;

    const convertedLeads = leads.rows.filter(
      function (l) {
        return l.status === "Converted";
      }
    ).length;

    let customerHtml = "";

    if (customers.rows.length === 0) {
      customerHtml = "<p>No customers found.</p>";
    } else {
      customers.rows.forEach(function (c) {
        customerHtml +=
          '<div class="item customerItem">' +
          "<b>" +
          escapeHtml(c.name) +
          "</b><br>" +
          "Phone: " +
          escapeHtml(c.phone || "-") +
          "<br>" +
          "Email: " +
          escapeHtml(c.email || "-") +
          "<br>" +
          "Address: " +
          escapeHtml(c.address || "-") +
          '<div class="actions">' +
          '<a href="/customers/edit/' +
          c.id +
          '"><button class="edit">Edit</button></a>' +
          '<form method="POST" action="/customers/delete/' +
          c.id +
          '" style="display:inline" onsubmit="return confirm(\'Delete this customer?\')">' +
          '<button class="danger">Delete</button>' +
          "</form>" +
          "</div>" +
          "</div>";
      });
    }

    let leadHtml = "";

    if (leads.rows.length === 0) {
      leadHtml = "<p>No leads found.</p>";
    } else {
      leads.rows.forEach(function (l) {
        leadHtml +=
          '<div class="item leadItem">' +
          "<b>" +
          escapeHtml(l.name) +
          "</b><br>" +
          "Phone: " +
          escapeHtml(l.phone || "-") +
          "<br>" +
          "Email: " +
          escapeHtml(l.email || "-") +
          "<br>" +
          "Source: " +
          escapeHtml(l.source || "-") +
          "<br>" +
          "Status: " +
          escapeHtml(l.status || "-") +
          "<br>" +
          "Follow-up: " +
          escapeHtml(l.follow_up_date || "-") +
          "<br>" +
          "Notes: " +
          escapeHtml(l.notes || "-") +
          '<div class="actions">' +
          '<a href="/leads/edit/' +
          l.id +
          '"><button class="edit">Edit</button></a>' +
          '<form method="POST" action="/leads/delete/' +
          l.id +
          '" style="display:inline" onsubmit="return confirm(\'Delete this lead?\')">' +
          '<button class="danger">Delete</button>' +
          "</form>" +
          "</div>" +
          "</div>";
      });
    }

    const content =
      '<div class="navbar">' +
      "<h2>CRM Dashboard</h2>" +
      '<div><span>Admin</span><a href="/logout">Logout</a></div>' +
      "</div>" +

      '<div class="container">' +

      '<div class="cards">' +
      '<div class="card"><h3>Customers</h3><div class="number">' +
      customers.rows.length +
      "</div></div>" +

      '<div class="card"><h3>Total Leads</h3><div class="number">' +
      leads.rows.length +
      "</div></div>" +

      '<div class="card"><h3>New Leads</h3><div class="number">' +
      newLeads +
      "</div></div>" +

      '<div class="card"><h3>Converted</h3><div class="number">' +
      convertedLeads +
      "</div></div>" +
      "</div>" +

      '<div class="grid">' +

      '<div class="section">' +
      "<h2>Add Customer</h2>" +
      '<form method="POST" action="/customers/add">' +
      '<input name="name" placeholder="Customer Name" required>' +
      '<input name="phone" placeholder="Phone">' +
      '<input type="email" name="email" placeholder="Email">' +
      '<textarea name="address" placeholder="Address"></textarea>' +
      '<button type="submit">Add Customer</button>' +
      "</form>" +
      "</div>" +

      '<div class="section">' +
      "<h2>Add Lead</h2>" +
      '<form method="POST" action="/leads/add">' +
      '<input name="name" placeholder="Lead Name" required>' +
      '<input name="phone" placeholder="Phone">' +
      '<input type="email" name="email" placeholder="Email">' +

      '<select name="source">' +
      '<option value="WhatsApp">WhatsApp</option>' +
      '<option value="Website">Website</option>' +
      '<option value="Facebook Ads">Facebook Ads</option>' +
      '<option value="Instagram">Instagram</option>' +
      '<option value="Google Ads">Google Ads</option>' +
      '<option value="Referral">Referral</option>' +
      '<option value="Other">Other</option>' +
      "</select>" +

      '<select name="status">' +
      '<option value="New">New</option>' +
      '<option value="Contacted">Contacted</option>' +
      '<option value="Interested">Interested</option>' +
      '<option value="Follow-up">Follow-up</option>' +
      '<option value="Converted">Converted</option>' +
      '<option value="Lost">Lost</option>' +
      "</select>" +

      '<input type="date" name="follow_up_date">' +
      '<textarea name="notes" placeholder="Notes"></textarea>' +
      '<button type="submit">Add Lead</button>' +
      "</form>" +
      "</div>" +

      "</div>" +

      '<div class="section">' +
      "<h2>Customers</h2>" +
      '<input class="search" id="customerSearch" placeholder="Search customer..." onkeyup="searchCustomers()">' +
      '<div id="customerList">' +
      customerHtml +
      "</div>" +
      "</div>" +

      '<div class="section">' +
      "<h2>Leads</h2>" +
      '<input class="search" id="leadSearch" placeholder="Search lead..." onkeyup="searchLeads()">' +
      '<div id="leadList">' +
      leadHtml +
      "</div>" +
      "</div>" +

      "</div>" +

      "<script>" +

      "function searchCustomers(){" +
      "var value=document.getElementById('customerSearch').value.toLowerCase();" +
      "document.querySelectorAll('.customerItem').forEach(function(item){" +
      "item.style.display=item.innerText.toLowerCase().includes(value)?'block':'none';" +
      "});" +
      "}" +

      "function searchLeads(){" +
      "var value=document.getElementById('leadSearch').value.toLowerCase();" +
      "document.querySelectorAll('.leadItem').forEach(function(item){" +
      "item.style.display=item.innerText.toLowerCase().includes(value)?'block':'none';" +
      "});" +
      "}" +

      "</script>";

    res.send(page("CRM Dashboard", content));
  } catch (error) {
    console.error(error);
    res.status(500).send("Dashboard error");
  }
});

/* ADD CUSTOMER */

app.post("/customers/add", requireLogin, async (req, res) => {
  try {
    const name = (req.body.name || "").trim();

    if (!name) {
      return res.send("Customer name required");
    }

    await pool.query(
      "INSERT INTO customers(name,phone,email,address) VALUES($1,$2,$3,$4)",
      [
        name,
        req.body.phone || "",
        req.body.email || "",
        req.body.address || ""
      ]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Customer add error");
  }
});

/* EDIT CUSTOMER */

app.get("/customers/edit/:id", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM customers WHERE id=$1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Customer not found");
    }

    const c = result.rows[0];

    const content =
      '<div class="container">' +
      '<div class="section">' +
      "<h2>Edit Customer</h2>" +
      '<form method="POST" action="/customers/edit/' +
      c.id +
      '">' +
      '<input name="name" value="' +
      escapeHtml(c.name) +
      '" placeholder="Customer Name" required>' +
      '<input name="phone" value="' +
      escapeHtml(c.phone) +
      '" placeholder="Phone">' +
      '<input type="email" name="email" value="' +
      escapeHtml(c.email) +
      '" placeholder="Email">' +
      '<textarea name="address" placeholder="Address">' +
      escapeHtml(c.address) +
      "</textarea>" +
      '<button type="submit">Save Changes</button> ' +
      '<a href="/"><button type="button">Cancel</button></a>' +
      "</form>" +
      "</div>" +
      "</div>";

    res.send(page("Edit Customer", content));
  } catch (error) {
    console.error(error);
    res.status(500).send("Edit customer error");
  }
});

app.post("/customers/edit/:id", requireLogin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE customers SET name=$1,phone=$2,email=$3,address=$4 WHERE id=$5",
      [
        req.body.name,
        req.body.phone || "",
        req.body.email || "",
        req.body.address || "",
        req.params.id
      ]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Customer update error");
  }
});

/* DELETE CUSTOMER */

app.post("/customers/delete/:id", requireLogin, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM customers WHERE id=$1",
      [req.params.id]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Customer delete error");
  }
});

/* ADD LEAD */

app.post("/leads/add", requireLogin, async (req, res) => {
  try {
    const name = (req.body.name || "").trim();

    if (!name) {
      return res.send("Lead name required");
    }

    await pool.query(
      `INSERT INTO leads
      (name,phone,email,source,status,follow_up_date,notes)
      VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [
        name,
        req.body.phone || "",
        req.body.email || "",
        req.body.source || "Other",
        req.body.status || "New",
        req.body.follow_up_date || null,
        req.body.notes || ""
      ]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Lead add error");
  }
});

/* EDIT LEAD */

app.get("/leads/edit/:id", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM leads WHERE id=$1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Lead not found");
    }

    const l = result.rows[0];

    const content =
      '<div class="container">' +
      '<div class="section">' +
      "<h2>Edit Lead</h2>" +
      '<form method="POST" action="/leads/edit/' +
      l.id +
      '">' +

      '<input name="name" value="' +
      escapeHtml(l.name) +
      '" placeholder="Lead Name" required>' +

      '<input name="phone" value="' +
      escapeHtml(l.phone) +
      '" placeholder="Phone">' +

      '<input type="email" name="email" value="' +
      escapeHtml(l.email) +
      '" placeholder="Email">' +

      '<select name="source">' +
      '<option value="WhatsApp" ' +
      selected("WhatsApp", l.source) +
      ">WhatsApp</option>" +
      '<option value="Website" ' +
      selected("Website", l.source) +
      ">Website</option>" +
      '<option value="Facebook Ads" ' +
      selected("Facebook Ads", l.source) +
      ">Facebook Ads</option>" +
      '<option value="Instagram" ' +
      selected("Instagram", l.source) +
      ">Instagram</option>" +
      '<option value="Google Ads" ' +
      selected("Google Ads", l.source) +
      ">Google Ads</option>" +
      '<option value="Referral" ' +
      selected("Referral", l.source) +
      ">Referral</option>" +
      '<option value="Other" ' +
      selected("Other", l.source) +
      ">Other</option>" +
      "</select>" +

      '<select name="status">' +
      '<option value="New" ' +
      selected("New", l.status) +
      ">New</option>" +
      '<option value="Contacted" ' +
      selected("Contacted", l.status) +
      ">Contacted</option>" +
      '<option value="Interested" ' +
      selected("Interested", l.status) +
      ">Interested</option>" +
      '<option value="Follow-up" ' +
      selected("Follow-up", l.status) +
      ">Follow-up</option>" +
      '<option value="Converted" ' +
      selected("Converted", l.status) +
      ">Converted</option>" +
      '<option value="Lost" ' +
      selected("Lost", l.status) +
      ">Lost</option>" +
      "</select>" +

      '<input type="date" name="follow_up_date" value="' +
      (l.follow_up_date || "") +
      '">' +

      '<textarea name="notes" placeholder="Notes">' +
      escapeHtml(l.notes) +
      "</textarea>" +

      '<button type="submit">Save Changes</button> ' +
      '<a href="/"><button type="button">Cancel</button></a>' +

      "</form>" +
      "</div>" +
      "</div>";

    res.send(page("Edit Lead", content));
  } catch (error) {
    console.error(error);
    res.status(500).send("Edit lead error");
  }
});

app.post("/leads/edit/:id", requireLogin, async (req, res) => {
  try {
    await pool.query(
      `UPDATE leads
       SET name=$1,
           phone=$2,
           email=$3,
           source=$4,
           status=$5,
           follow_up_date=$6,
           notes=$7
       WHERE id=$8`,
      [
        req.body.name,
        req.body.phone || "",
        req.body.email || "",
        req.body.source || "Other",
        req.body.status || "New",
        req.body.follow_up_date || null,
        req.body.notes || "",
        req.params.id
      ]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Lead update error");
  }
});

/* DELETE LEAD */

app.post("/leads/delete/:id", requireLogin, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM leads WHERE id=$1",
      [req.params.id]
    );

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Lead delete error");
  }
});

/* START */

async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, function () {
      console.log("CRM API running on port " + PORT);
    });
  } catch (error) {
    console.error("Database setup error:", error);
  }
}

startServer();