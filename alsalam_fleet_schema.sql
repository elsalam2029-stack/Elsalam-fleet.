-- شركة السلام للمقاولات والتوريدات العمومية
-- PostgreSQL schema v1. Run with a dedicated database owner during setup.
-- Never put production passwords, TOTP seeds, or database credentials in this file.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS fleet;
SET search_path TO fleet, public;

CREATE TABLE IF NOT EXISTS roles (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  role_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS permissions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  permission_key TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS app_users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  department TEXT NOT NULL DEFAULT 'الإدارة',
  password_hash TEXT NOT NULL,
  role_id BIGINT NOT NULL REFERENCES roles(id),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  -- TOTP secret must be encrypted by the application before storage.
  totp_secret_ciphertext TEXT,
  totp_confirmed_at TIMESTAMPTZ,
  recovery_code_hashes TEXT[] NOT NULL DEFAULT '{}',
  last_login_at TIMESTAMPTZ,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (NOT mfa_enabled OR (totp_secret_ciphertext IS NOT NULL AND totp_confirmed_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS vehicles (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  plate_number TEXT NOT NULL,
  vehicle_type TEXT,
  make TEXT,
  model TEXT,
  manufacture_year INTEGER CHECK (manufacture_year BETWEEN 1900 AND 2200),
  chassis_number TEXT,
  engine_number TEXT,
  color TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Plate numbers are indexed but not unique: source data can contain duplicate/exception rows
-- that must be reviewed rather than silently discarded.
CREATE INDEX IF NOT EXISTS ix_vehicles_plate ON vehicles (plate_number);
CREATE INDEX IF NOT EXISTS ix_vehicles_active ON vehicles (is_active);

CREATE TABLE IF NOT EXISTS drivers (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name TEXT NOT NULL,
  employee_number TEXT,
  phone TEXT,
  license_number TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_drivers_name ON drivers (full_name);
CREATE INDEX IF NOT EXISTS ix_drivers_active ON drivers (is_active);

CREATE TABLE IF NOT EXISTS locations (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  location_name TEXT NOT NULL UNIQUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS overtime_rules (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  rule_name TEXT NOT NULL,
  effective_from DATE NOT NULL,
  effective_to DATE,
  normal_hours NUMERIC(5,2) NOT NULL DEFAULT 10 CHECK (normal_hours >= 0),
  multi_vehicle_overtime BOOLEAN NOT NULL DEFAULT TRUE,
  overtime_multiplier NUMERIC(5,2) NOT NULL DEFAULT 1 CHECK (overtime_multiplier >= 0),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (effective_to IS NULL OR effective_to >= effective_from)
);
CREATE INDEX IF NOT EXISTS ix_overtime_rules_dates ON overtime_rules (effective_from, effective_to);

CREATE TABLE IF NOT EXISTS trip_sheets (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sheet_number TEXT NOT NULL UNIQUE,
  trip_date DATE NOT NULL,
  driver_id BIGINT NOT NULL REFERENCES drivers(id) ON DELETE RESTRICT,
  vehicle_id BIGINT NOT NULL REFERENCES vehicles(id) ON DELETE RESTRICT,
  origin_location_id BIGINT REFERENCES locations(id) ON DELETE SET NULL,
  destination_location_id BIGINT REFERENCES locations(id) ON DELETE SET NULL,
  origin_text TEXT,
  destination_text TEXT,
  start_at TIMESTAMPTZ NOT NULL,
  end_at TIMESTAMPTZ NOT NULL,
  start_odometer NUMERIC(12,1) CHECK (start_odometer >= 0),
  end_odometer NUMERIC(12,1) CHECK (end_odometer >= 0),
  actual_hours NUMERIC(8,2) GENERATED ALWAYS AS (GREATEST(0, EXTRACT(EPOCH FROM (end_at - start_at)) / 3600.0)) STORED,
  overtime_hours NUMERIC(8,2) NOT NULL DEFAULT 0 CHECK (overtime_hours >= 0),
  deviations_hours NUMERIC(8,2) NOT NULL DEFAULT 0 CHECK (deviations_hours >= 0),
  deviation_notes TEXT,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'مكتمل' CHECK (status IN ('مسودة','مكتمل','ملغي')),
  created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  updated_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (end_at >= start_at),
  CHECK (end_odometer IS NULL OR start_odometer IS NULL OR end_odometer >= start_odometer)
);
CREATE INDEX IF NOT EXISTS ix_trip_sheets_date ON trip_sheets (trip_date);
CREATE INDEX IF NOT EXISTS ix_trip_sheets_driver_date ON trip_sheets (driver_id, trip_date);
CREATE INDEX IF NOT EXISTS ix_trip_sheets_vehicle_date ON trip_sheets (vehicle_id, trip_date);

CREATE TABLE IF NOT EXISTS fuel_prices (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  fuel_type TEXT NOT NULL,
  effective_from DATE NOT NULL,
  price_per_liter NUMERIC(12,4) NOT NULL CHECK (price_per_liter > 0),
  notes TEXT,
  created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (fuel_type, effective_from)
);
CREATE INDEX IF NOT EXISTS ix_fuel_prices_lookup ON fuel_prices (fuel_type, effective_from DESC);

CREATE TABLE IF NOT EXISTS fuel_entries (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  refuel_date DATE NOT NULL,
  vehicle_id BIGINT NOT NULL REFERENCES vehicles(id) ON DELETE RESTRICT,
  driver_id BIGINT REFERENCES drivers(id) ON DELETE SET NULL,
  fuel_type TEXT NOT NULL,
  amount_paid NUMERIC(12,2) NOT NULL CHECK (amount_paid >= 0),
  price_per_liter NUMERIC(12,4) NOT NULL CHECK (price_per_liter > 0),
  liters NUMERIC(12,3) GENERATED ALWAYS AS (ROUND(amount_paid / NULLIF(price_per_liter, 0), 3)) STORED,
  odometer NUMERIC(12,1) NOT NULL CHECK (odometer >= 0),
  station_name TEXT,
  receipt_number TEXT,
  notes TEXT,
  created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_fuel_entries_vehicle_date ON fuel_entries (vehicle_id, refuel_date, id);
CREATE INDEX IF NOT EXISTS ix_fuel_entries_driver_date ON fuel_entries (driver_id, refuel_date);

-- Snapshot the historically valid fuel price at entry time; old entries never change
-- when a later price is added. Application may omit price_per_liter on insert.
CREATE OR REPLACE FUNCTION set_fuel_entry_price() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE applicable_price NUMERIC(12,4);
BEGIN
  SELECT fp.price_per_liter INTO applicable_price
  FROM fuel_prices fp
  WHERE fp.fuel_type = NEW.fuel_type AND fp.effective_from <= NEW.refuel_date
  ORDER BY fp.effective_from DESC LIMIT 1;
  IF applicable_price IS NULL THEN
    RAISE EXCEPTION 'No fuel price configured for type % on %', NEW.fuel_type, NEW.refuel_date;
  END IF;
  NEW.price_per_liter := applicable_price;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_set_fuel_entry_price ON fuel_entries;
CREATE TRIGGER trg_set_fuel_entry_price
BEFORE INSERT OR UPDATE OF refuel_date, fuel_type ON fuel_entries
FOR EACH ROW EXECUTE FUNCTION set_fuel_entry_price();

-- Computes distance since the previous recorded refuel of the same vehicle and km/l.
CREATE OR REPLACE VIEW fuel_economy AS
WITH ordered AS (
  SELECT f.*,
         LAG(f.odometer) OVER (PARTITION BY f.vehicle_id ORDER BY f.refuel_date, f.id) AS previous_odometer
  FROM fuel_entries f
)
SELECT o.id AS fuel_entry_id, o.refuel_date, o.vehicle_id, v.plate_number,
       o.driver_id, d.full_name AS driver_name, o.fuel_type, o.amount_paid,
       o.price_per_liter, o.liters, o.odometer, o.previous_odometer,
       CASE WHEN o.previous_odometer IS NOT NULL AND o.odometer >= o.previous_odometer
            THEN o.odometer - o.previous_odometer END AS distance_km,
       CASE WHEN o.previous_odometer IS NOT NULL AND o.odometer > o.previous_odometer AND o.liters > 0
            THEN ROUND((o.odometer - o.previous_odometer) / o.liters, 2) END AS km_per_liter
FROM ordered o JOIN vehicles v ON v.id = o.vehicle_id
LEFT JOIN drivers d ON d.id = o.driver_id;

-- Detects drivers recorded on more than one vehicle on a given date.
CREATE OR REPLACE VIEW drivers_multiple_vehicles_daily AS
SELECT trip_date, driver_id, d.full_name AS driver_name,
       COUNT(DISTINCT vehicle_id) AS vehicle_count,
       ARRAY_AGG(DISTINCT v.plate_number ORDER BY v.plate_number) AS plates
FROM trip_sheets t
JOIN drivers d ON d.id = t.driver_id
JOIN vehicles v ON v.id = t.vehicle_id
WHERE t.status <> 'ملغي'
GROUP BY trip_date, driver_id, d.full_name
HAVING COUNT(DISTINCT vehicle_id) > 1;

-- Daily overtime is aggregated by driver/day so trips using multiple vehicles are counted together.
CREATE OR REPLACE VIEW driver_daily_overtime_calculation AS
WITH daily AS (
  SELECT t.trip_date, t.driver_id, d.full_name AS driver_name,
         SUM(t.actual_hours) AS total_actual_hours,
         COUNT(DISTINCT t.vehicle_id) AS vehicle_count,
         ARRAY_AGG(DISTINCT v.plate_number ORDER BY v.plate_number) AS plates,
         SUM(t.overtime_hours) AS approved_overtime_hours,
         SUM(t.deviations_hours) AS deviations_hours
  FROM trip_sheets t
  JOIN drivers d ON d.id = t.driver_id
  JOIN vehicles v ON v.id = t.vehicle_id
  WHERE t.status <> 'ملغي'
  GROUP BY t.trip_date, t.driver_id, d.full_name
), applicable AS (
  SELECT daily.*, r.normal_hours, r.multi_vehicle_overtime, r.overtime_multiplier,
         ROW_NUMBER() OVER (PARTITION BY daily.trip_date, daily.driver_id
                            ORDER BY r.effective_from DESC NULLS LAST, r.id DESC) AS rule_rank
  FROM daily
  LEFT JOIN overtime_rules r ON r.effective_from <= daily.trip_date
    AND (r.effective_to IS NULL OR r.effective_to >= daily.trip_date)
    AND r.is_active = TRUE
)
SELECT trip_date, driver_id, driver_name, total_actual_hours, vehicle_count, plates,
       COALESCE(normal_hours, 10) AS normal_hours,
       (vehicle_count > 1) AS used_multiple_vehicles,
       CASE WHEN vehicle_count > 1 AND COALESCE(multi_vehicle_overtime, TRUE)
            THEN GREATEST(0, total_actual_hours - COALESCE(normal_hours, 10)) * COALESCE(overtime_multiplier, 1)
            ELSE GREATEST(0, total_actual_hours - COALESCE(normal_hours, 10)) * COALESCE(overtime_multiplier, 1)
       END AS suggested_overtime_hours,
       approved_overtime_hours, deviations_hours
FROM applicable WHERE rule_rank = 1;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_log_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_log_user ON audit_log (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS backup_runs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  status TEXT NOT NULL CHECK (status IN ('running','success','failed')),
  storage_reference TEXT,
  size_bytes BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
  checksum_sha256 TEXT,
  error_summary TEXT,
  triggered_by TEXT NOT NULL DEFAULT 'scheduler'
);

INSERT INTO roles(role_key, display_name, description, is_system) VALUES
 ('admin','مدير النظام','إدارة كاملة للنظام والمستخدمين والإعدادات',TRUE),
 ('operations','مسؤول التشغيل','خطوط السير والإضافي ومتابعة المركبات',TRUE),
 ('fuel_officer','مسؤول التفويلات','إدخال التفويلات وأسعار الوقود',TRUE),
 ('vehicle_affairs','شؤون السيارات','إدارة بيانات السيارات والسائقين',TRUE),
 ('reviewer','مراجع تقارير','قراءة التقارير والبيانات فقط',TRUE)
ON CONFLICT (role_key) DO NOTHING;

INSERT INTO permissions(permission_key, description) VALUES
 ('dashboard.read','عرض لوحة التحكم'), ('trips.read','عرض خطوط السير'), ('trips.write','إضافة وتعديل خطوط السير'),
 ('trips.cancel','إلغاء خطوط السير'), ('overtime.read','عرض تقارير الإضافي'), ('overtime.adjust','تعديل الإضافي والانحرافات'),
 ('fuel.read','عرض التفويلات'), ('fuel.write','إضافة وتعديل التفويلات'), ('fuel_prices.manage','إدارة أسعار الوقود'),
 ('vehicles.read','عرض السيارات'), ('vehicles.manage','إضافة وتعديل وتعطيل السيارات'),
 ('drivers.read','عرض السائقين'), ('drivers.manage','إضافة وتعديل وتعطيل السائقين'),
 ('reports.read','عرض التقارير'), ('reports.print','طباعة وتصدير التقارير'),
 ('users.manage','إدارة المستخدمين والصلاحيات'), ('settings.manage','إدارة قواعد النظام'),
 ('audit.read','عرض سجل التدقيق'), ('backups.manage','إدارة ومراجعة النسخ الاحتياطية')
ON CONFLICT (permission_key) DO NOTHING;

-- Admin gets all permissions. Other roles are intentionally least-privilege defaults.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.role_key='admin' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.permission_key IN
 ('dashboard.read','trips.read','trips.write','trips.cancel','overtime.read','overtime.adjust','vehicles.read','drivers.read','reports.read','reports.print')
WHERE r.role_key='operations' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.permission_key IN
 ('dashboard.read','fuel.read','fuel.write','fuel_prices.manage','vehicles.read','drivers.read','reports.read','reports.print')
WHERE r.role_key='fuel_officer' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.permission_key IN
 ('dashboard.read','vehicles.read','vehicles.manage','drivers.read','drivers.manage','reports.read','reports.print')
WHERE r.role_key='vehicle_affairs' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.permission_key IN
 ('dashboard.read','trips.read','overtime.read','fuel.read','vehicles.read','drivers.read','reports.read','reports.print')
WHERE r.role_key='reviewer' ON CONFLICT DO NOTHING;

INSERT INTO overtime_rules(rule_name, effective_from, normal_hours, multi_vehicle_overtime)
SELECT 'القاعدة الافتراضية', DATE '2026-01-01', 10, TRUE
WHERE NOT EXISTS (SELECT 1 FROM overtime_rules);

INSERT INTO fuel_prices(fuel_type, effective_from, price_per_liter, notes)
VALUES ('جاز', DATE '2026-09-01', 10, 'سعر أولي وارد في النموذج التجريبي')
ON CONFLICT (fuel_type, effective_from) DO NOTHING;

COMMIT;
