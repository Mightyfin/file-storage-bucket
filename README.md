# MightyFin Document Service

Status: **initial secure-upload slice implemented locally**

This shared service owns document metadata, upload authorization, integrity verification,
classification and controlled retrieval for every MightyFin product. PostgreSQL stores metadata;
an S3-compatible object store holds encrypted file bytes. EFaaS, lending, partner and future apps
store only the returned Document ID or evidence reference.

Implemented boundaries:

- OIDC tenant/environment scope and `documents.write` / `documents.read` authorization;
- canonical Party verification before an upload session is issued;
- opaque object keys with no names or identity numbers;
- short-lived presigned PUT and GET URLs;
- declared SHA-256, MIME type and byte-length validation after upload;
- immutable document identity and append-only audit history;
- tenant and environment isolation;
- explicit purpose, classification, consent and source references;
- provider-neutral S3 endpoint configuration.

Not yet production-ready: malware scanning, content disarm, production KMS integration, legal-hold
operations, automated retention, reviewer UI, cross-product consent decisions and multi-node
object-store durability still require implementation and acceptance testing.

Local dependencies:

```text
infrastructure/local-development/object-storage/seaweedfs/compose.yaml
```

The service requires its own GitHub repository before publication.
