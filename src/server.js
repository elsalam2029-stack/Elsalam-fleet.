import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import rateLimit from 'express-rate-limit';
import { pool } from './db.js';
import { requireAuth, verifyPassword } from './auth.js';

const app = express();
const PgSession = connectPgSimple(session);
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be configured with at least 32 characters.');
}
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '200kb' }));
app.use(session({
  store: new PgSession({
    pool,
    schemaName: 'fleet',
    tableName: 'http_sessions',
    createTableIfMissing: true
  }),
  name: 'elsalam.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too_many_login_attempts' }
});

app.get('/api/health', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!username || !password || username.length > 100 || password.length > 1024) {
    return res.status(400).json({ error: 'invalid_credentials_format' });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, full_name, department, password_hash, is_active,
              must_change_password, failed_login_attempts, locked_until
         FROM fleet.app_users
        WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    const genericError = { error: 'invalid_username_or_password' };

    if (!user || !user.is_active) return res.status(401).json(genericError);
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'account_temporarily_locked' });
    }

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      await pool.query(
        `UPDATE fleet.app_users
            SET failed_login_attempts = LEAST(failed_login_attempts + 1, 100),
                locked_until = CASE
                  WHEN failed_login_attempts + 1 >= 8 THEN now() + interval '15 minutes'
                  ELSE locked_until END,
                updated_at = now()
          WHERE id = $1`,
        [user.id]
      );
      return res.status(401).json(genericError);
    }

    await pool.query(
      `UPDATE fleet.app_users
          SET failed_login_attempts = 0, locked_until = NULL,
              last_login_at = now(), updated_at = now()
        WHERE id = $1`,
      [user.id]
    );

    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => err ? reject(err) : resolve());
    });
    req.session.userId = user.id;
    res.json({
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        department: user.department,
        must_change_password: user.must_change_password
      }
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'logout_failed' });
    res.clearCookie('elsalam.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.status(204).end();
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Permission checks and business endpoints are deliberately added in subsequent steps.
// Do not expose database CRUD until role/permission enforcement is implemented.
app.use('/api', (_req, res) => res.status(501).json({ error: 'endpoint_not_implemented' }));

app.use((err, _req, res, _next) => {
  console.error('Request failed:', err.message);
  res.status(500).json({ error: 'internal_server_error' });
});

app.listen(port, () => {
  console.log(`Al Salam Fleet API listening on port ${port}`);
});
