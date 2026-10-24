import pg from 'pg';

const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required. Copy .env.example to .env and configure it.');
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // For managed PostgreSQL requiring TLS, configure provider-specific SSL settings.
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => {
  console.error('Unexpected idle PostgreSQL client error:', err.message);
});
