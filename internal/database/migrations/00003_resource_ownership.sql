-- +goose Up
ALTER TABLE documents ADD COLUMN owner_type VARCHAR(40);
ALTER TABLE documents ADD COLUMN owner_id VARCHAR(128);
UPDATE documents SET owner_type='PARTY', owner_id=party_id;
ALTER TABLE documents ALTER COLUMN owner_type SET NOT NULL;
ALTER TABLE documents ALTER COLUMN owner_id SET NOT NULL;
ALTER TABLE documents ALTER COLUMN party_id DROP NOT NULL;
ALTER TABLE documents ADD CONSTRAINT documents_owner_type_check CHECK (
  owner_type IN ('PARTY','LEGAL_ENTITY','ORGANISATIONAL_UNIT','CASE','PRODUCT_RESOURCE','REGULATORY_RECORD')
);
ALTER TABLE documents ADD CONSTRAINT documents_party_owner_check CHECK (
  (owner_type='PARTY' AND party_id IS NOT NULL AND owner_id=party_id) OR
  (owner_type<>'PARTY' AND party_id IS NULL)
);
CREATE INDEX documents_owner_scope_idx
  ON documents(tenant_id,environment,owner_type,owner_id,created_at DESC);
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

-- +goose Down
DROP INDEX IF EXISTS documents_owner_scope_idx;
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_party_owner_check;
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_owner_type_check;
ALTER TABLE documents ALTER COLUMN party_id SET NOT NULL;
ALTER TABLE documents DROP COLUMN IF EXISTS owner_id;
ALTER TABLE documents DROP COLUMN IF EXISTS owner_type;
