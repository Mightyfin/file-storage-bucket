# Assessment evidence verification

`POST /v1/documents/{id}/evidence-verification`

Required token scope: `documents.evidence.verify`. Token tenant, environment,
subject and application context must be explicit; environment must match this
deployment. Neither request headers nor body can override tenant/environment.
No permissions are automatically granted by this change.

Body: `{"party_id":"party_...","sha256":"<64 lowercase hex characters>"}`.

For payment/case-specific attachments, include `resource_reference` with the
owning record ID. It must match the document's `source_reference` as well as the
party, tenant, environment, digest and clean status in the same locked lookup.
The response echoes `resource_reference` only after that check. An empty supplied
reference is rejected. Old callers may omit it; payment verifiers must require
it and must reject a legacy response without the exact binding. Resource context
must come from the authorized owning service, not an arbitrary upload claim.

The owning application service must derive the party from its authorised case,
not blindly pass through a browser-supplied party id. This endpoint verifies only
PARTY-owned documents: correct tenant, environment, owner and immutable digest;
available status and clean malware scan. Other ownership models fail closed.
It returns metadata, not storage keys, file contents or download URLs.

Successful checks append `evidence_version_checked` with actor/application and
correlation id. Document read and audit write use one transaction with a shared
row lock. Audit failure fails the verification. Recheck before a decision or
download; this result is not a permanent clearance or a credit decision.

403: absent scope/tenant/environment or foreign deployment environment.
404: missing document or wrong tenant/subject/environment (no existence leak).
409: invalid digest, version mismatch or unavailable/unclean document.

## Remaining integration

Case binding and access remain owned by onboarding/credit services. They still
need authenticated environment propagation, authorised subject resolution,
versioned case bindings, information-request/resubmission and a strictly scoped
download path. The legacy download service-account fallback is unchanged and
must not be used for this new integration. No UI upload flow is enabled yet.

## Tests

HTTP contract tests exercise dedicated scope, tenant/environment requirements,
header/body override denial. PostgreSQL tests use temporary tables on a disposable
database via DOCUMENT_EVIDENCE_TEST_DATABASE_URL and verify tenant/environment/
party isolation, exact digest, pending/infected/failed scans and audit attribution.
