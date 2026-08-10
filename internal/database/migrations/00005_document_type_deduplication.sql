-- +goose Up
ALTER TABLE documents
  DROP CONSTRAINT IF EXISTS documents_tenant_id_environment_source_application_source_r_key;

ALTER TABLE documents
  ADD CONSTRAINT documents_source_document_hash_key
  UNIQUE (tenant_id, environment, source_application, source_reference, document_type, sha256_hex);

-- +goose Down
ALTER TABLE documents
  DROP CONSTRAINT IF EXISTS documents_source_document_hash_key;

ALTER TABLE documents
  ADD CONSTRAINT documents_tenant_id_environment_source_application_source_r_key
  UNIQUE (tenant_id, environment, source_application, source_reference, sha256_hex);
