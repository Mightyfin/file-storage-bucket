-- +goose Up
ALTER TABLE documents ADD COLUMN idempotency_key VARCHAR(128);
ALTER TABLE documents ADD COLUMN request_hash CHAR(64);
ALTER TABLE documents ADD CONSTRAINT documents_idempotency_pair CHECK (
  (idempotency_key IS NULL AND request_hash IS NULL) OR
  (idempotency_key IS NOT NULL AND request_hash IS NOT NULL)
);
CREATE UNIQUE INDEX documents_idempotency_idx
  ON documents(tenant_id, environment, source_application, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS documents_idempotency_idx;
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_idempotency_pair;
ALTER TABLE documents DROP COLUMN IF EXISTS request_hash;
ALTER TABLE documents DROP COLUMN IF EXISTS idempotency_key;
