-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_document_identity_mutation() RETURNS trigger AS $$
BEGIN
  IF NEW.public_id<>OLD.public_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.environment<>OLD.environment
     OR NEW.party_id IS DISTINCT FROM OLD.party_id OR NEW.owner_type IS DISTINCT FROM OLD.owner_type
     OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.object_key<>OLD.object_key OR NEW.sha256_hex<>OLD.sha256_hex THEN
    RAISE EXCEPTION 'document identity and integrity fields are immutable';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_document_audit_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'document audit is append-only'; END; $$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  public_id VARCHAR(64) NOT NULL UNIQUE,
  tenant_id VARCHAR(64) NOT NULL,
  environment VARCHAR(20) NOT NULL CHECK(environment IN ('local','dev','sandbox','staging','production')),
  party_id VARCHAR(64) NOT NULL,
  source_application VARCHAR(120) NOT NULL,
  source_reference VARCHAR(120),
  consent_reference VARCHAR(120),
  document_type VARCHAR(60) NOT NULL,
  purpose VARCHAR(120) NOT NULL,
  classification VARCHAR(30) NOT NULL CHECK(classification IN ('INTERNAL','CONFIDENTIAL','RESTRICTED')),
  original_filename VARCHAR(255) NOT NULL,
  content_type VARCHAR(120) NOT NULL,
  size_bytes BIGINT NOT NULL CHECK(size_bytes>0 AND size_bytes<=52428800),
  sha256_hex CHAR(64) NOT NULL CHECK(sha256_hex ~ '^[0-9a-f]{64}$'),
  bucket_name VARCHAR(63) NOT NULL,
  object_key VARCHAR(512) NOT NULL UNIQUE,
  status VARCHAR(30) NOT NULL DEFAULT 'pending_upload' CHECK(status IN ('pending_upload','uploaded','quarantined','available','rejected','expired')),
  scan_status VARCHAR(30) NOT NULL DEFAULT 'pending' CHECK(scan_status IN ('pending','clean','infected','failed','not_required')),
  retention_category VARCHAR(60) NOT NULL,
  retain_until TIMESTAMPTZ,
  upload_expires_at TIMESTAMPTZ NOT NULL,
  uploaded_at TIMESTAMPTZ,
  created_by VARCHAR(200) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,environment,source_application,source_reference,sha256_hex)
);
CREATE INDEX documents_party_scope_idx ON documents(tenant_id,environment,party_id,created_at DESC);
CREATE TRIGGER documents_identity_immutable BEFORE UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION reject_document_identity_mutation();

CREATE TABLE document_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  action VARCHAR(60) NOT NULL,
  actor_subject VARCHAR(200) NOT NULL,
  actor_application VARCHAR(120) NOT NULL,
  correlation_id VARCHAR(128) NOT NULL,
  reason VARCHAR(500),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER document_audit_immutable BEFORE UPDATE OR DELETE ON document_audit_events FOR EACH ROW EXECUTE FUNCTION reject_document_audit_mutation();

-- +goose Down
DROP TABLE IF EXISTS document_audit_events,documents;
DROP FUNCTION IF EXISTS reject_document_audit_mutation();
DROP FUNCTION IF EXISTS reject_document_identity_mutation();
