# Staff bank-payment evidence

Status: implemented locally and tested; deployment and Green end-to-end UAT pending.

Set `DOCUMENT_PAYMENT_RAILS_BASE_URL` to the trusted internal Payment Rails API.
Missing configuration denies payment document operations. Staff tokens must be
valid for Documents and Payment Rails and carry the sandbox/live environment.
Rails decides staff-client admission and checks roles and the actual payment.
No tenant token or caller-selected file owner can grant access.

The route prefix is:
`/v1/manual-payments/tenants/{tenant}/payments/{payment}/documents`

| Method | Suffix | Operation |
|---|---|---|
| POST | `/upload-sessions` | Create a restricted payment receipt upload |
| PUT | `/{id}/content` | Upload bytes, pending the malware scan |
| GET | `/{id}` | Inspect the upload/scan status |
| GET | `/{id}/content?sha256=…` | Download the exact clean version |
| POST | `/{id}/evidence-verification?sha256=…` | Verify the exact clean version for Rails |

Upload-session body: filename, content_type, size_bytes, sha256. Supply an
Idempotency-Key. Party, tenant, purpose and payment reference come from the
authorized payment, not browser input. Accepted content types and size limits
remain those of the shared Document service. Uploaded files remain quarantined
until the normal scanner completes; this workflow does not bypass scanning.

Each operation calls the owning payment's document-access endpoint with the
original staff token. The response must match tenant, environment, actor,
payment, document, digest and intent. Bank documents use purpose
`manual_bank_payment` and a payment-specific scope produced only by this
resolver. Ordinary document read/download/evidence endpoints and legacy
tenantless lookups cannot access them. A receipt upload is not confirmation
that money moved. Rails requires a separate review, then downstream accounting.

Tests cover mismatched grants, dependency failures, tenant denial and database
isolation of the protected files. These do not substitute for a deployed
upload → scan → attach → independent review test or bank-statement review.
