
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;

const required = [
  "DATABASE_URL",
  "JWT_SECRET",
  "SETUP_SECRET",
  "FRONTEND_URL"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

if (
  process.env.JWT_SECRET.length < 32 ||
  process.env.SETUP_SECRET.length < 32
) {
  console.error("Secrets must contain at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: true }
    : undefined
});

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ["GET", "POST", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "1mb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
}));

app.use("/api/auth/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10
}));

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      full_name VARCHAR(150) NOT NULL,
      username VARCHAR(80) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'employee'
        CHECK (role IN ('admin', 'employee')),
      department VARCHAR(100),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function makeToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "8h", issuer: "alsalam-fleet" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: "يلزم تسجيل الدخول" });
  }

  try {
    req.token = jwt.verify(match[1], process.env.JWT_SECRET, {
      issuer: "alsalam-fleet"
    });
    next();
  } catch {
    return res.status(401).json({
      error: "انتهت صلاحية الجلسة. سجل الدخول مرة أخرى."
    });
  }
}

async function loadUser(req, res, next) {
  try {
    const result = await pool.query(
      `SELECT id, full_name, username, role, department, is_active
       FROM employees WHERE id = $1`,
      [req.token.sub]
    );

    if (!result.rowCount || !result.rows[0].is_active) {
      return res.status(401).json({ error: "الحساب غير متاح" });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "هذه العملية متاحة للمدير فقط"
    });
  }
  next();
}

function validUsername(value) {
  return typeof value === "string" &&
    /^[a-zA-Z0-9._-]{3,80}$/.test(value);
}

function validPassword(value) {
  return typeof value === "string" && value.length >= 12;
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({
      ok: false,
      database: "unavailable"
    });
  }
});

/* إنشاء المدير الأول مرة واحدة فقط */
app.post("/api/setup/admin", async (req, res, next) => {
  const provided = req.get("X-Setup-Secret") || "";

  if (
    provided.length !== process.env.SETUP_SECRET.length ||
    provided !== process.env.SETUP_SECRET
  ) {
    return res.status(403).json({ error: "إعداد غير مصرح به" });
  }

  const client = await pool.connect();

  try {
    const { full_name, username, password } = req.body || {};

    if (
      typeof full_name !== "string" ||
      full_name.trim().length < 2 ||
      full_name.length > 150 ||
      !validUsername(username) ||
      !validPassword(password)
    ) {
      return res.status(400).json({
        error: "أدخل الاسم واسم المستخدم وكلمة مرور من 12 حرفًا على الأقل"
      });
    }

    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [73190521]);

    const existing = await client.query(
      "SELECT id FROM employees WHERE role = 'admin' LIMIT 1"
    );

    if (existing.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "تم إنشاء حساب المدير بالفعل"
      });
    }

    const hash = await argon2.hash(password);

    const result = await client.query(
      `INSERT INTO employees
       (full_name, username, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       RETURNING id, full_name, username, role`,
      [full_name.trim(), username, hash]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "تم إنشاء حساب المدير",
      user: result.rows[0]
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.code === "23505") {
      return res.status(409).json({
        error: "اسم المستخدم مستخدم بالفعل"
      });
    }
    next(err);
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 80 ||
      password.length > 200
    ) {
      return res.status(400).json({
        error: "أدخل اسم المستخدم وكلمة المرور"
      });
    }

    const result = await pool.query(
      `SELECT id, full_name, username, password_hash,
              role, department, is_active
       FROM employees WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (
      !user ||
      !user.is_active ||
      !(await argon2.verify(user.password_hash, password))
    ) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    res.json({
      token: makeToken(user),
      user: {
        id: user.id,
        full_name: user.full_name,
        username: user.username,
        role: user.role,
        department: user.department
      }
    });
  } catch (err) {
    next(err);
  }
});

app.get(
  "/api/auth/me",
  authenticate,
  loadUser,
  (req, res) => res.json({ user: req.user })
);

/* المسارات التالية للمدير فقط */
app.use("/api/employees", authenticate, loadUser, adminOnly);

app.get("/api/employees", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, username, role, department,
              is_active, created_at
       FROM employees ORDER BY id DESC`
    );
    res.json({ employees: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/employees", async (req, res, next) => {
  try {
    const { full_name, username, password, department } = req.body || {};

    if (
      typeof full_name !== "string" ||
      full_name.trim().length < 2 ||
      full_name.length > 150 ||
      !validUsername(username) ||
      !validPassword(password) ||
      (department != null &&
       (typeof department !== "string" || department.length > 100))
    ) {
      return res.status(400).json({
        error: "راجع الاسم واسم المستخدم وكلمة المرور والقسم"
      });
    }

    const hash = await argon2.hash(password);

    const result = await pool.query(
      `INSERT INTO employees
       (full_name, username, password_hash, role, department)
       VALUES ($1, $2, $3, 'employee', $4)
       RETURNING id, full_name, username, role, department,
                 is_active, created_at`,
      [full_name.trim(), username, hash, department || null]
    );

    res.status(201).json({ employee: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "اسم المستخدم مستخدم بالفعل"
      });
    }
    next(err);
  }
});

app.patch("/api/employees/:id/status", async (req, res, next) => {
  try {
    const id = req.params.id;

    if (!/^[1-9]\d*$/.test(id)) {
      return res.status(400).json({ error: "رقم الحساب غير صحيح" });
    }

    if (typeof req.body?.is_active !== "boolean") {
      return res.status(400).json({
        error: "is_active يجب أن تكون true أو false"
      });
    }

    if (String(req.user.id) === id && !req.body.is_active) {
      return res.status(400).json({
        error: "لا يمكنك تعطيل حسابك الحالي"
      });
    }

    const result = await pool.query(
      `UPDATE employees SET is_active = $1
       WHERE id = $2 AND role = 'employee'
       RETURNING id, full_name, username, role, department, is_active`,
      [req.body.is_active, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "الموظف غير موجود" });
    }

    res.json({ employee: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error("API error:", err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });
});

async function start() {
  await initDatabase();
  app.listen(port, () => {
    console.log(`AlSalam Fleet API listening on ${port}`);
  });
}

start().catch((err) => {
  console.error("Server startup failed:", err.message);
  process.exit(1);
});
