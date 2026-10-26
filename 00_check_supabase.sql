-- Read-only check. This query does not create, modify, or delete anything.
SELECT
    current_database() AS database_name,
    current_user AS database_user,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'fleet') AS fleet_schema_exists,
    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'fleet' AND table_type = 'BASE TABLE') AS existing_fleet_tables;
