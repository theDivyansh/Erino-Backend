const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const sqlite3 = require("sqlite3").verbose();
const util = require("util");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";

//MIDDLEWARE
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

//DATABASE
const db = new sqlite3.Database(process.env.DB_FILE || "leads.db");

db.runAsync = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};
db.getAsync = util.promisify(db.get.bind(db));
db.allAsync = util.promisify(db.all.bind(db));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS leads (
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
  )`);
});

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log("No token provided");
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log("Authenticated user:", decoded.id, decoded.email);
    next();
  } catch (err) {
    console.error("JWT error:", err);
    res.status(401).json({ error: "Invalid token." });
  }
};

//filter handling
const buildWhereClause = (filters) => {
  let whereClause = "";
  let params = [];

  if (!filters || Object.keys(filters).length === 0) {
    console.log("No filters applied");
    return { whereClause, params };
  }

  console.log(
    "Building where clause for filters:",
    JSON.stringify(filters, null, 2)
  );
  const conditions = [];

  for (const [field, filterDef] of Object.entries(filters)) {
    if (!filterDef) continue;

    if (filterDef.operator && filterDef.condition1 && filterDef.condition2) {
      const subConditions = [];
      [filterDef.condition1, filterDef.condition2].forEach((cond) => {
        if (!cond || !cond.type) return;
        const { sql, values } = buildSingleCondition(field, cond);
        if (sql) {
          subConditions.push(sql);
          params.push(...values);
        }
      });
      if (subConditions.length > 0) {
        const joiner = filterDef.operator === "OR" ? " OR " : " AND ";
        conditions.push(`(${subConditions.join(joiner)})`);
      }
    } else {
      const { sql, values } = buildSingleCondition(field, filterDef);
      if (sql) {
        conditions.push(sql);
        params.push(...values);
      }
    }
  }

  if (conditions.length > 0) {
    whereClause = `WHERE ${conditions.join(" AND ")}`;
  }

  console.log("Generated WHERE clause:", whereClause);
  console.log("Parameters:", params);

  return { whereClause, params };
};

const buildSingleCondition = (field, cond) => {
  let sql = "";
  let values = [];

  console.log(`Building condition for field: ${field}`, cond);

  try {
    switch (cond.type) {
      case "equals":
        sql = `${field} = ?`;
        values.push(cond.filter);
        break;

      case "contains":
        sql = `${field} LIKE ?`;
        values.push(`%${cond.filter}%`);
        break;

      case "startsWith":
        sql = `${field} LIKE ?`;
        values.push(`${cond.filter}%`);
        break;

      case "endsWith":
        sql = `${field} LIKE ?`;
        values.push(`%${cond.filter}`);
        break;

      case "notEqual":
        sql = `${field} != ?`;
        values.push(cond.filter);
        break;

      case "in":
        if (Array.isArray(cond.values) && cond.values.length > 0) {
          const placeholders = cond.values.map(() => "?").join(",");
          sql = `${field} IN (${placeholders})`;
          values.push(...cond.values);
        }
        break;

      case "greaterThan":
      case "gt":
        sql = `${field} > ?`;
        values.push(cond.filter);
        break;

      case "lessThan":
      case "lt":
        sql = `${field} < ?`;
        values.push(cond.filter);
        break;

      case "between":
        if (cond.filter != null && cond.filterTo != null) {
          sql = `${field} BETWEEN ? AND ?`;
          values.push(cond.filter, cond.filterTo);
        }
        break;

      case "on":
        sql = `DATE(${field}) = DATE(?)`;
        values.push(cond.date || cond.filter);
        break;

      case "before":
        sql = `DATE(${field}) < DATE(?)`;
        values.push(cond.date || cond.filter);
        break;

      case "after":
        sql = `DATE(${field}) > DATE(?)`;
        values.push(cond.date || cond.filter);
        break;

      case "true":
        sql = `${field} = ?`;
        values.push(1);
        break;

      case "false":
        sql = `${field} = ?`;
        values.push(0);
        break;

      default:
        console.warn(`Unknown filter type: ${cond.type} for field: ${field}`);
        break;
    }
  } catch (error) {
    console.error(`Error building condition for field ${field}:`, error);
  }

  console.log(`Generated condition: ${sql} with values:`, values);
  return { sql, values };
};

//AUTH ROUTES
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, first_name, last_name } = req.body;
    if (!email || !password || !first_name || !last_name)
      return res.status(400).json({ error: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.runAsync(
      "INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)",
      [email, hashedPassword, first_name, last_name]
    );

    const user = await db.getAsync(
      "SELECT id, email, first_name, last_name FROM users WHERE id = ?",
      [result.lastID]
    );

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
    console.error("Registration error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const user = await db.getAsync("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
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
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout successful" });
});

// Current user
app.get("/api/auth/me", authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// LEADS ROUTES
app.post("/api/leads", authenticateToken, async (req, res) => {
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
      return res.status(400).json({
        error: "Required fields missing: first_name, last_name, email, source",
      });
    }

    console.log("Creating lead for user:", req.user.id);

    const result = await db.runAsync(
      `INSERT INTO leads (first_name,last_name,email,phone,company,city,state,source,status,score,lead_value,last_activity_at,is_qualified,user_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
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
        req.user.id,
      ]
    );

    const lead = await db.getAsync("SELECT * FROM leads WHERE id = ?", [
      result.lastID,
    ]);

    console.log("Lead created successfully:", lead.id);
    res.status(201).json(lead);
  } catch (err) {
    console.error("Create lead error:", err);
    if (err.message.includes("UNIQUE constraint failed")) {
      return res
        .status(400)
        .json({ error: "Lead with this email already exists" });
    }
    res.status(500).json({ error: "Failed to create lead" });
  }
});

// GET leads
app.get("/api/leads", authenticateToken, async (req, res) => {
  try {
    console.log("Fetching leads for user:", req.user.id);
    console.log("Query parameters:", req.query);

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;

    let filters = {};
    if (req.query.filters) {
      try {
        filters = JSON.parse(req.query.filters);
        console.log("Parsed filters:", JSON.stringify(filters, null, 2));
      } catch (parseError) {
        console.error("Filter parsing error:", parseError);
        return res.status(400).json({ error: "Invalid filters format" });
      }
    }

    const { whereClause, params } = buildWhereClause(filters);

    const userClause = whereClause
      ? `${whereClause} AND user_id = ?`
      : "WHERE user_id = ?";

    const allParams = [...params, req.user.id];

    console.log("Final query params:", allParams);
    console.log("User clause:", userClause);

    const totalQuery = `SELECT COUNT(*) as total FROM leads ${userClause}`;
    console.log("Total query:", totalQuery);

    const totalResult = await db.getAsync(totalQuery, allParams);
    console.log("Total result:", totalResult);

    const dataQuery = `SELECT * FROM leads ${userClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    const dataParams = [...allParams, limit, offset];
    console.log("Data query:", dataQuery);
    console.log("Data params:", dataParams);

    const leads = await db.allAsync(dataQuery, dataParams);
    console.log(`Found ${leads.length} leads`);

    const response = {
      data: leads,
      page,
      limit,
      total: totalResult.total,
      totalPages: Math.ceil(totalResult.total / limit),
    };

    console.log("Response summary:", {
      count: leads.length,
      page: response.page,
      total: response.total,
      totalPages: response.totalPages,
    });

    res.json(response);
  } catch (err) {
    console.error("Fetch leads error:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch leads", details: err.message });
  }
});

app.get("/api/leads/:id", authenticateToken, async (req, res) => {
  try {
    const leadId = req.params.id;
    console.log(`Fetching lead ${leadId} for user ${req.user.id}`);

    if (!leadId || isNaN(parseInt(leadId))) {
      return res.status(400).json({ error: "Invalid lead ID" });
    }

    const lead = await db.getAsync(
      "SELECT * FROM leads WHERE id = ? AND user_id = ?",
      [leadId, req.user.id]
    );

    if (!lead) {
      console.log(`Lead ${leadId} not found for user ${req.user.id}`);
      return res.status(404).json({ error: "Lead not found" });
    }

    console.log(`Lead ${leadId} found successfully`);
    res.json(lead);
  } catch (err) {
    console.error("Fetch single lead error:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch lead", details: err.message });
  }
});

app.put("/api/leads/:id", authenticateToken, async (req, res) => {
  try {
    const leadId = req.params.id;
    console.log(`Updating lead ${leadId} for user ${req.user.id}`);

    if (!leadId || isNaN(parseInt(leadId))) {
      return res.status(400).json({ error: "Invalid lead ID" });
    }

    const {
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
      is_qualified,
    } = req.body;

    if (!first_name || !last_name || !email || !source) {
      return res.status(400).json({
        error: "Required fields missing: first_name, last_name, email, source",
      });
    }

    const result = await db.runAsync(
      `UPDATE leads SET 
        first_name=?, last_name=?, email=?, phone=?, company=?, city=?, state=?, 
        source=?, status=?, score=?, lead_value=?, last_activity_at=?, is_qualified=?, 
        updated_at=CURRENT_TIMESTAMP 
       WHERE id=? AND user_id=?`,
      [
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
        leadId,
        req.user.id,
      ]
    );

    if (result.changes === 0) {
      console.log(
        `Lead ${leadId} not found or not owned by user ${req.user.id}`
      );
      return res.status(404).json({
        error: "Lead not found or you don't have permission to update it",
      });
    }

    const lead = await db.getAsync(
      "SELECT * FROM leads WHERE id = ? AND user_id = ?",
      [leadId, req.user.id]
    );

    console.log(`Lead ${leadId} updated successfully`);
    res.json(lead);
  } catch (err) {
    console.error("Update lead error:", err);
    if (err.message.includes("UNIQUE constraint failed")) {
      return res
        .status(400)
        .json({ error: "Email already exists for another lead" });
    }
    res
      .status(500)
      .json({ error: "Failed to update lead", details: err.message });
  }
});

//DELETE lead
app.delete("/api/leads/:id", authenticateToken, async (req, res) => {
  try {
    const leadId = req.params.id;
    console.log(`Deleting lead ${leadId} for user ${req.user.id}`);

    if (!leadId || isNaN(parseInt(leadId))) {
      return res.status(400).json({ error: "Invalid lead ID" });
    }

    const existingLead = await db.getAsync(
      "SELECT id FROM leads WHERE id = ? AND user_id = ?",
      [leadId, req.user.id]
    );

    if (!existingLead) {
      console.log(
        `Lead ${leadId} not found or not owned by user ${req.user.id}`
      );
      return res.status(404).json({
        error: "Lead not found or you don't have permission to delete it",
      });
    }

    const result = await db.runAsync(
      "DELETE FROM leads WHERE id = ? AND user_id = ?",
      [leadId, req.user.id]
    );

    if (result.changes === 0) {
      console.log(`Failed to delete lead ${leadId} - no changes made`);
      return res.status(404).json({ error: "Lead not found" });
    }

    console.log(`Lead ${leadId} deleted successfully`);
    res.json({ message: "Lead deleted successfully", deletedId: leadId });
  } catch (err) {
    console.error("Delete lead error:", err);
    res
      .status(500)
      .json({ error: "Failed to delete lead", details: err.message });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res
    .status(500)
    .json({ error: "Internal server error", details: err.message });
});

// Error handler
app.use((req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ error: "Route not found" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
