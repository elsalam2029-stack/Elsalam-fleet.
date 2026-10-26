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
