'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(s => s.trim()) : false,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (err) {
    console.error('Health database check failed:', err.message);
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

// This is a secure-by-default starter, not the complete application API yet.
// Do not expose business data endpoints until authentication, authorization,
// validation, audit logging, and frontend integration have been completed.
app.get('/api', (_req, res) => res.json({
  name: 'AlSalam Fleet API',
  status: 'starter',
  message: 'Health endpoint available. Business endpoints are not enabled yet.'
}));

app.use((err, _req, res, _next) => {
  console.error('Unhandled request error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => console.log(`AlSalam Fleet API listening on port ${port}`));
async function shutdown(signal) {
  console.log(`${signal} received; shutting down`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
