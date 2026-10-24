import argon2 from 'argon2';
import { pool } from './db.js';

export async function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'authentication_required' });
  }
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.full_name, u.department, u.is_active,
              u.must_change_password, r.role_key, r.display_name AS role_name
         FROM fleet.app_users u
         JOIN fleet.roles r ON r.id = u.role_id
        WHERE u.id = $1 AND u.is_active = TRUE`,
      [req.session.userId]
    );
    if (!result.rowCount) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'account_inactive' });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

export async function verifyPassword(password, hash) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
