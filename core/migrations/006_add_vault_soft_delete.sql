-- Migration 006: Soft deletes for vaults (BE-044 / issue #281).
-- Deletion now sets `deleted_at` instead of removing the row, so vault history
-- and associated data remain available for audit and reconciliation. Default
-- queries filter out soft-deleted rows; an admin restore clears `deleted_at`.

ALTER TABLE vaults ADD COLUMN deleted_at TIMESTAMP NULL;
CREATE INDEX IF NOT EXISTS idx_vaults_deleted_at ON vaults(deleted_at);
