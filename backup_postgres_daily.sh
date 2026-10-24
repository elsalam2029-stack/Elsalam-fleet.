#!/usr/bin/env bash
# Daily PostgreSQL backup template for the server administrator.
# Configure DB_NAME, BACKUP_DIR, RETENTION_DAYS, and PG* connection variables securely
# in the server environment or a root-readable environment file, not in source control.
set -Eeuo pipefail

: "${DB_NAME:?Set DB_NAME in the server environment}"
: "${BACKUP_DIR:?Set BACKUP_DIR to a protected backup directory}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/${DB_NAME}_${STAMP}.dump"
TMP="${OUT}.tmp"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

pg_dump --format=custom --no-owner --no-acl --dbname="$DB_NAME" --file="$TMP"
mv "$TMP" "$OUT"
chmod 600 "$OUT"
sha256sum "$OUT" > "${OUT}.sha256"
find "$BACKUP_DIR" -maxdepth 1 -type f -name "${DB_NAME}_*.dump" -mtime "+${RETENTION_DAYS}" -delete
find "$BACKUP_DIR" -maxdepth 1 -type f -name "${DB_NAME}_*.dump.sha256" -mtime "+${RETENTION_DAYS}" -delete
printf 'Backup complete: %s\n' "$OUT"
