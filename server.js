const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";

// MIDDLEWARE
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

// DATABASE (better-sqlite3 is sync by default)
const db = new Database(process.env.DB_FILE || "leads.db");

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    company TEXT,
    city TEXT,
    state TEXT,
    source TEXT CHECK(source IN ('website','facebook_ads','google_ads','referral','events','other')) NOT NULL,
    status TEXT CHECK(status IN ('new','contacted','qualified','lost','won')) DEFAULT 'new',
    score INTEGER CHECK(score >= 0 AND score <= 100) DEFAULT 0,
    lead_value REAL DEFAULT 0,
    last_activity_at DATETIME,
    is_qualified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// AUTH MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token." });
  }
};

// AUTH ROUTES
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, first_name, last_name } = req.body;
    if (!email || !password || !first_name || !last_name)
      return res.status(400).json({ error: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare(
      "INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)"
    );
    const result = stmt.run(email, hashedPassword, first_name, last_name);

    const user = db
      .prepare(
        "SELECT id, email, first_name, last_name FROM users WHERE id = ?"
      )
      .get(result.lastInsertRowid);

    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "24h" });
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(201).json({ message: "User created successfully", user });
  } catch (err) {
    if (err.message.includes("UNIQUE constraint failed")) {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      return res.status(401).json({ error: "Invalid credentials" });

    const safeUser = {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
    };

    const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: "24h" });
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({ message: "Login successful", user: safeUser });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout successful" });
});

app.get("/api/auth/me", authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// LEADS ROUTES
app.post("/api/leads", authenticateToken, (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      phone,
      company,
      city,
      state,
      source,
      status = "new",
      score = 0,
      lead_value = 0,
      last_activity_at,
      is_qualified = false,
    } = req.body;

    if (!first_name || !last_name || !email || !source) {
      return res.status(400).json({ error: "Required fields missing" });
    }

    const stmt = db.prepare(
      `INSERT INTO leads (first_name,last_name,email,phone,company,city,state,source,status,score,lead_value,last_activity_at,is_qualified,user_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    );
    const result = stmt.run(
      first_name,
      last_name,
      email,
      phone,
      company,
      city,
      state,
      source,
      status,
      score,
      lead_value,
      last_activity_at,
      is_qualified ? 1 : 0,
      req.user.id
    );

    const lead = db
      .prepare("SELECT * FROM leads WHERE id = ?")
      .get(result.lastInsertRowid);
    res.status(201).json(lead);
  } catch (err) {
    if (err.message.includes("UNIQUE constraint failed")) {
      return res
        .status(400)
        .json({ error: "Lead with this email already exists" });
    }
    res.status(500).json({ error: "Failed to create lead" });
  }
});

app.get("/api/leads", authenticateToken, (req, res) => {
  try {
    const leads = db
      .prepare("SELECT * FROM leads WHERE user_id = ? ORDER BY created_at DESC")
      .all(req.user.id);
    res.json(leads);
  } catch {
    res.status(500).json({ error: "Failed to fetch leads" });
  }
});

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

// ERROR HANDLER
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
