
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const required = [
  "DATABASE_URL",
  "SESSION_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD_HASH"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

const production = process.env.NODE_ENV === "production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: production ? { rejectUnauthorized: false } : false
});

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

const sessionMiddleware = session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "bsc.sid",
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const safeUser = u => ({
  id: u.id,
  name: u.name,
  email: u.email,
  phone: u.phone,
  account_type: u.account_type,
  shop_name: u.shop_name,
  role: u.role,
  status: u.status,
  wallet_balance: u.wallet_balance,
  created_at: u.created_at
});

// AUTOMATIC DATABASE SETUP
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT,
      password_hash TEXT NOT NULL,
      account_type TEXT NOT NULL DEFAULT 'creator',
      shop_name TEXT,
      shop_details JSONB NOT NULL DEFAULT '{}'::jsonb,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      wallet_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      method TEXT,
      reference TEXT,
      note TEXT,
      processed_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS transactions_user_created_idx
    ON transactions(user_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS transactions_status_created_idx
    ON transactions(status, created_at DESC);

    CREATE TABLE IF NOT EXISTS platform_settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    INSERT INTO platform_settings(key,value) VALUES
    ('platform_name','"Bangla Super Chat"'),
    ('commission_percent','10'),
    ('min_withdrawal','300'),
    ('payment_methods','["bKash","Nagad","Rocket","Upay"]')
    ON CONFLICT(key) DO NOTHING;
  `);

  console.log("DATABASE_SCHEMA_READY");
}

async function ensureAdmin() {
  const email = process.env.ADMIN_EMAIL.toLowerCase().trim();

  const result = await pool.query(
    "SELECT id FROM users WHERE email=$1",
    [email]
  );

  if (!result.rowCount) {
    await pool.query(
      `INSERT INTO users(name,email,password_hash,role,account_type)
       VALUES($1,$2,$3,'admin','creator')`,
      [
        "Platform Administrator",
        email,
        process.env.ADMIN_PASSWORD_HASH
      ]
    );

    console.log("INITIAL_ADMIN_CREATED");
  } else {
    await pool.query(
      "UPDATE users SET role='admin' WHERE email=$1",
      [email]
    );
  }
}

const requireAuth = asyncRoute(async (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please sign in." });
  }

  const result = await pool.query(
    "SELECT * FROM users WHERE id=$1",
    [req.session.userId]
  );

  if (!result.rowCount || result.rows[0].status !== "active") {
    req.session.destroy(() => {});
    return res.status(401).json({ error: "Account unavailable." });
  }

  req.user = result.rows[0];
  next();
});

const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }
  next();
};

const emitUser = (id, event, data) =>
  io.to(`user:${id}`).emit(event, data);

const emitAdmins = (event, data) =>
  io.to("admins").emit(event, data);

app.get("/api/health", (req, res) => {
  res.json({ ok: true, name: "Bangla Super Chat" });
});

// REGISTER
app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const {
    name, email, password, phone,
    accountType, shopName, shopDetails
  } = req.body || {};

  if (!name || !email || !password || String(password).length < 10) {
    return res.status(400).json({
      error: "Name, email and password of at least 10 characters required."
    });
  }

  const hash = await bcrypt.hash(String(password), 12);

  const result = await pool.query(
    `INSERT INTO users
    (name,email,phone,password_hash,account_type,shop_name,shop_details)
    VALUES($1,$2,$3,$4,$5,$6,$7)
    RETURNING *`,
    [
      String(name).trim(),
      String(email).toLowerCase().trim(),
      phone || null,
      hash,
      accountType === "shop" ? "shop" : "creator",
      shopName || null,
      shopDetails || {}
    ]
  );

  req.session.userId = result.rows[0].id;

  emitAdmins("admin:new-user", safeUser(result.rows[0]));

  res.status(201).json({ user: safeUser(result.rows[0]) });
}));

// LOGIN
app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase().trim();

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (
    !result.rowCount ||
    !(await bcrypt.compare(
      String(req.body?.password || ""),
      result.rows[0].password_hash
    ))
  ) {
    return res.status(401).json({
      error: "Email or password is incorrect."
    });
  }

  const user = result.rows[0];

  if (user.status !== "active") {
    return res.status(403).json({
      error: "This account is blocked."
    });
  }

  req.session.userId = user.id;
  res.json({ user: safeUser(user) });
}));

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

// USER DASHBOARD
app.get("/api/dashboard", requireAuth, asyncRoute(async (req, res) => {
  const [totals, history] = await Promise.all([
    pool.query(`
      SELECT
      COUNT(*) FILTER (
        WHERE status IN ('approved','completed')
        AND type='donation'
      ) AS donations_count,
      COALESCE(SUM(amount) FILTER (
        WHERE status IN ('approved','completed')
        AND type='donation'
      ),0) AS donations_total
      FROM transactions WHERE user_id=$1
    `, [req.user.id]),

    pool.query(`
      SELECT id,type,amount,status,method,reference,note,
      created_at,processed_at
      FROM transactions
      WHERE user_id=$1
      ORDER BY created_at DESC LIMIT 100
    `, [req.user.id])
  ]);

  res.json({
    user: safeUser(req.user),
    stats: totals.rows[0],
    transactions: history.rows
  });
}));

// WITHDRAWAL REQUEST
app.post("/api/withdrawals", requireAuth, asyncRoute(async (req, res) => {
  const amount = Number(req.body?.amount);

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: "Invalid amount." });
  }

  const setting = await pool.query(
    "SELECT value FROM platform_settings WHERE key='min_withdrawal'"
  );

  const minimum = Number(setting.rows[0]?.value ?? 300);

  if (amount < minimum) {
    return res.status(400).json({
      error: `Minimum withdrawal is ৳${minimum}.`
    });
  }

  const result = await pool.query(
    `INSERT INTO transactions
    (user_id,type,amount,status,method,reference,note)
    VALUES($1,'withdrawal',$2,'pending',$3,$4,$5)
    RETURNING *`,
    [
      req.user.id,
      amount,
      req.body.method || null,
      req.body.account || null,
      req.body.note || null
    ]
  );

  emitAdmins("admin:new-transaction", {
    ...result.rows[0],
    user_name: req.user.name,
    user_email: req.user.email
  });

  res.status(201).json({ transaction: result.rows[0] });
}));

// ADMIN OVERVIEW
app.get("/api/admin/overview", requireAuth, requireAdmin,
asyncRoute(async (req, res) => {
  const [users, transactions, totals, settings] = await Promise.all([
    pool.query(`
      SELECT id,name,email,phone,account_type,shop_name,
      role,status,wallet_balance,created_at
      FROM users ORDER BY created_at DESC LIMIT 500
    `),

    pool.query(`
      SELECT t.*,u.name AS user_name,u.email AS user_email,
      u.account_type,u.shop_name
      FROM transactions t
      JOIN users u ON u.id=t.user_id
      ORDER BY t.created_at DESC LIMIT 500
    `),

    pool.query(`
      SELECT
      COUNT(*) FILTER(WHERE role='user') AS users,
      COUNT(*) FILTER(WHERE account_type='shop') AS shops,
      (SELECT COUNT(*) FROM transactions
       WHERE status='pending') AS pending,
      (SELECT COALESCE(SUM(amount),0) FROM transactions
       WHERE type='donation'
       AND status IN ('approved','completed')) AS donation_volume
      FROM users
    `),

    pool.query("SELECT key,value FROM platform_settings ORDER BY key")
  ]);

  res.json({
    users: users.rows,
    transactions: transactions.rows,
    stats: totals.rows[0],
    settings: settings.rows
  });
}));

// ADMIN TRANSACTION DECISION
app.post("/api/admin/transactions/:id/decision",
requireAuth, requireAdmin,
asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const decision = req.body?.decision;

  if (
    !Number.isSafeInteger(id) ||
    !["approve", "reject", "cancel"].includes(decision)
  ) {
    return res.status(400).json({ error: "Invalid decision." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM transactions WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Transaction not found." });
    }

    const tx = result.rows[0];

    if (tx.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Transaction already processed."
      });
    }

    const next =
      decision === "approve" ? "approved" :
      decision === "reject" ? "rejected" : "cancelled";

    if (decision === "approve" && tx.type === "withdrawal") {
      const user = await client.query(
        "SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE",
        [tx.user_id]
      );

      if (Number(user.rows[0].wallet_balance) < Number(tx.amount)) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: "Insufficient wallet balance."
        });
      }

      await client.query(
        "UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2",
        [tx.amount, tx.user_id]
      );
    }

    await client.query(
      `UPDATE transactions
       SET status=$1,processed_by=$2,processed_at=NOW()
       WHERE id=$3`,
      [next, req.user.id, id]
    );

    await client.query("COMMIT");

    const updated = { ...tx, status: next };

    emitUser(tx.user_id, "user:transaction-updated", updated);
    emitUser(tx.user_id, "user:wallet-updated", {});
    emitAdmins("admin:transaction-updated", updated);

    res.json({ transaction: updated });

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

// BLOCK / UNBLOCK USERS
app.post("/api/admin/users/:id/status",
requireAuth, requireAdmin,
asyncRoute(async (req, res) => {
  const status = req.body?.status;

  if (!["active", "blocked"].includes(status)) {
    return res.status(400).json({ error: "Invalid status." });
  }

  const result = await pool.query(
    `UPDATE users SET status=$1
     WHERE id=$2 AND role<>'admin'
     RETURNING id,status`,
    [status, req.params.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "User not found." });
  }

  emitUser(req.params.id, "user:account-status", { status });

  res.json({ user: result.rows[0] });
}));

// PLATFORM SETTINGS
app.put("/api/admin/settings/:key",
requireAuth, requireAdmin,
asyncRoute(async (req, res) => {
  const key = req.params.key;
  const value = req.body?.value;

  if (!["commission_percent", "min_withdrawal", "payment_methods"].includes(key)) {
    return res.status(400).json({ error: "Setting not allowed." });
  }

  if (
    key === "commission_percent" &&
    (!Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > 50)
  ) {
    return res.status(400).json({ error: "Invalid commission." });
  }

  if (
    key === "min_withdrawal" &&
    (!Number.isFinite(Number(value)) || Number(value) < 1)
  ) {
    return res.status(400).json({ error: "Invalid minimum withdrawal." });
  }

  await pool.query(`
    INSERT INTO platform_settings(key,value,updated_at)
    VALUES($1,$2,NOW())
    ON CONFLICT(key)
    DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()
  `, [key, JSON.stringify(value)]);

  emitAdmins("admin:settings-updated", { key, value });

  res.json({ ok: true });
}));

// SOCKET AUTHENTICATION
io.on("connection", async socket => {
  const sessionData = socket.request.session;

  if (!sessionData?.userId) return;

  try {
    const result = await pool.query(
      "SELECT id,role FROM users WHERE id=$1 AND status='active'",
      [sessionData.userId]
    );

    if (!result.rowCount) return;

    socket.join(`user:${result.rows[0].id}`);

    if (result.rows[0].role === "admin") {
      socket.join("admins");
    }
  } catch (error) {
    console.error("Socket authentication failed:", error.message);
  }
});

// PAGE ROUTES
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error(error);

  if (error.code === "23505") {
    return res.status(409).json({
      error: "This email is already registered."
    });
  }

  res.status(500).json({
    error: "Server error. Please try again."
  });
});

// START SERVER ONLY AFTER DATABASE TABLES ARE READY
(async () => {
  try {
    await pool.query("SELECT 1");
    console.log("DATABASE_CONNECTED");

    await initializeDatabase();

    await ensureAdmin();

    const port = process.env.PORT || 3000;

    server.listen(port, () => {
      console.log("DATABASE_SCHEMA_READY");
      console.log(`Bangla Super Chat running on port ${port}`);
    });

  } catch (error) {
    console.error("STARTUP FAILED:", error);
    process.exit(1);
  }
})();
