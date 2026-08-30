-- Migration: Add COMPROMISED license status and enrich SecurityEvent table
-- Apply with: psql $DATABASE_URL -f add_compromised_security.sql

BEGIN;

-- ── 1. Add COMPROMISED to the LicenseStatus enum ──────────────────────────────
-- PostgreSQL does not allow removing enum values, only adding. Safe to run.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_enum
    WHERE enumlabel = 'COMPROMISED'
    AND   enumtypid = (SELECT oid FROM pg_type WHERE typname = 'LicenseStatus')
  ) THEN
    ALTER TYPE "LicenseStatus" ADD VALUE 'COMPROMISED' AFTER 'EXPIRED';
  END IF;
END;
$$;

-- ── 2. Add new columns to SecurityEvent ───────────────────────────────────────
ALTER TABLE "SecurityEvent"
  ADD COLUMN IF NOT EXISTS "severity"     TEXT NOT NULL DEFAULT 'INFO',
  ADD COLUMN IF NOT EXISTS "actionTaken"  TEXT,
  ADD COLUMN IF NOT EXISTS "discordSent"  BOOLEAN NOT NULL DEFAULT FALSE;

-- ── 3. Indexes for the new columns ────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS "SecurityEvent_severity_idx"   ON "SecurityEvent"("severity");
CREATE INDEX IF NOT EXISTS "SecurityEvent_licenseId_idx2" ON "SecurityEvent"("licenseId");

-- ── 4. revoke_reason on Session (for audit trail) ─────────────────────────────
ALTER TABLE "Session"
  ADD COLUMN IF NOT EXISTS "revokedReason" TEXT;

COMMIT;
