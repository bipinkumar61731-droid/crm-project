const session = require("express-session");
const bcrypt = require("bcryptjs");
const express = require("express");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());
app.use(
  session({
    secret: "change-this-secret-later",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);


const db = new Database("crm.db");

db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  address TEXT
)
`);

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
)
`);

const adminPassword = bcrypt.hashSync("Admin@123", 10);

const existingAdmin = db
  .prepare("SELECT * FROM users WHERE username = ?")
  .get("admin");

if (!existingAdmin) {
  db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  ).run("admin", adminPassword);
app.get("/login", (req, res) => {
  res.send(`
    <h2>CRM Login</h2>

    <form method="POST" action="/login">
      <input name="username" placeholder="Username" required>
      <br><br>
      <input name="password" type="password" placeholder="Password" required>
      <br><br>
      <button type="submit">Login</button>
    </form>
  `);
});

app.use(express.urlencoded({ extended: false }));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (!user) {
    return res.status(401).send("Invalid username or password");
  }

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.status(401).send("Invalid username or password");
  }

  req.session.userId = user.id;

  res.redirect("/");
});}app.get("/", (req, res) => {if 
(!req.session.userId) {
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

  <h1>📊 My CRM Dashboard</h1>

  <div class="box">
    <h2>Add Customer</h2>

    <input id="name" placeholder="Customer Name">
    <input id="phone" placeholder="Phone Number">
    <input id="email" placeholder="Email">
    <input id="address" placeholder="Address">

    <button onclick="addCustomer()">➕ Add Customer</button>
  </div>

  <div class="box">
    <h2>Customers</h2>

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

async function addCustomer() {

  const name = document.getElementById("name").value;
  const phone = document.getElementById("phone").value;
  const email = document.getElementById("email").value;
  const address = document.getElementById("address").value;

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
      name: name,
      phone: phone,
      email: email,
      address: address
    })
  });

  if (response.ok) {

    document.getElementById("name").value = "";
    document.getElementById("phone").value = "";
    document.getElementById("email").value = "";
    document.getElementById("address").value = "";

    loadCustomers();

    alert("Customer added successfully!");} else {
    alert("Customer add nahi hua");
  }
}

async function loadCustomers() {
  const response = await fetch("/customers");
  const customers = await response.json();

  const search = document.getElementById("search").value.toLowerCase();
  const container = document.getElementById("customers");

  container.innerHTML = "";

  const filtered = customers.filter(function(customer) {
    return (
      customer.name.toLowerCase().includes(search) ||
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
      "<strong>" + customer.name + "</strong><br>" +
      "📞 " + (customer.phone || "") + "<br>" +
      "📧 " + (customer.email || "") + "<br>" +
      "📍 " + (customer.address || "") +
      "<br><button onclick='editCustomer(" +
customer.id +
")'>✏️ Edit</button>" +
"<button class='delete' onclick='deleteCustomer(" +
customer.id +
")'>🗑 Delete</button>";
    container.appendChild(div);
  });
}
async function editCustomer(id) {
  const response = await fetch("/customers/" + id);
  const customer = await response.json();

  const name = prompt("Customer Name:", customer.name);
  if (name === null) return;

  const phone = prompt("Phone:", customer.phone);
  if (phone === null) return;

  const email = prompt("Email:", customer.email);
  if (email === null) return;

  const address = prompt("Address:", customer.address);
  if (address === null) return;

  await fetch("/customers/" + id, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name: name,
      phone: phone,
      email: email,
      address: address
    })
  });

  loadCustomers();
  alert("Customer updated successfully!");
}
async function deleteCustomer(id) {
  if (!confirm("Delete this customer?")) {
    return;
  }

  const response = await fetch("/customers/" + id, {
    method: "DELETE"
  });

  if (response.ok) {
    loadCustomers();
  }
}

loadCustomers();

</script>
</body>
</html>
  `);
});

app.get("/customers", (req, res) => {
  const customers = db
    .prepare("SELECT * FROM customers ORDER BY id DESC")
    .all();

  res.json(customers);
});

app.post("/customers", (req, res) => {
  const { name, phone, email, address } = req.body;

  if (!name) {
    return res.status(400).json({
      error: "Name is required"
    });
  }

  const result = db
    .prepare(
      "INSERT INTO customers (name, phone, email, address) VALUES (?, ?, ?, ?)"
    )
    .run(name, phone || "", email || "", address || "");

  res.status(201).json({
    id: result.lastInsertRowid,
    name,
    phone: phone || "",
    email: email || "",
    address: address || ""
  });
});

app.delete("/customers/:id", (req, res) => {
  const id = Number(req.params.id);

  const result = db
    .prepare("DELETE FROM customers WHERE id = ?")
    .run(id);

  if (result.changes === 0) {
    return res.status(404).json({
      error: "Customer not found"
    });
  }

  res.json({
    message: "Customer deleted successfully"
  });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("CRM API running at http://localhost:3000");
});