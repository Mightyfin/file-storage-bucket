# Bank-account verification evidence

Purpose `bank_account_verification` is private to its bank-account case.
Generic document access, receipt grants and statement grants do not confer
access. The trusted owner-service grant must supply case reference, owner type,
owner ID, tenant/environment and the original human actor/application.

Participant destinations use PARTY ownership and an explicit tenant. MightyFin
source accounts use LEGAL_ENTITY ownership with an empty tenant partition; do
not invent a participant or tenant to hold the lender's documents. Only this
dedicated, validated scope permits empty-tenant creation/completion. Existing
generic tenant creation rules are unchanged.

`BankAccountDocument`, `BankAccountEvidence` and `OpenBankAccountEvidence` check
exact case/owner/environment. Evidence additionally requires an available,
clean, exact SHA-256 version. Evidence checks/downloads produce audit events.
These methods do not certify the contents or available cash balance.

Dedicated HTTP routes are registered under
`/v1/bank-account-documents/{account}/documents`:

- POST `/upload-sessions` creates restricted evidence metadata.
- PUT `/{id}/content` uploads the file into quarantine for scanning.
- GET `/{id}` reads case-bound metadata.
- GET `/{id}/content` downloads an exact clean version.
- POST `/{id}/evidence-verification` verifies an exact clean version.

Every request requires exactly one scope: `tenant_id=...` or
`owner_scope=lender`. Download and verification also require `sha256`.
Payment Rails authorizes each intent against its stored case and staff roles
using the original bearer token. No caller-supplied owner or delegated identity
is accepted. Grant resolution has a five-second timeout, bounded response,
no redirects, and exact actor/environment/case/document/hash checks. A missing
or invalid grant prevents document access.

Status: domain/storage methods, disposable-PostgreSQL isolation tests, HTTP
routes and grant validation tests are implemented. HTTP tests use a synthetic
Payment Rails server and do not establish connected deployment readiness.
The Payment Rails document-verifier adapter, runtime configuration and full
connected bank-account workflow remain pending. No running deployment uses
these new methods yet. Green UAT is not complete.
