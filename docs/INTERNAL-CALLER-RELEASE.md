# Restricted internal document callers

Pending coordinated release. Tenantless credentials no longer imply unrestricted
document access. `DOCUMENT_TRUSTED_INTERNAL_CLIENTS` is a comma-separated list of
exact OIDC `azp` service-client IDs. Empty defaults to no legacy internal access;
wildcards and eFaaS tenant workload (`efc_...`) IDs are rejected at startup.

Only a verified token with an allowlisted authorised party, no tenant claim and
no tenant application claim receives the internal grant. Existing document scopes
remain required. Never populate this setting from a request header or token data.
The deployment environment still bounds access; missing environment is not
silently converted to sandbox inside document operations.

Before release, inventory current **confidential service-account-only** clients
that use the legacy generic upload/read/download routes, confirm their required
document scopes and disable interactive grants on those clients. Configure only
the reviewed IDs in each environment. Do not include staff console or tenant
clients to bypass case authorization. Record the inventory and approval with the
deployment, and test approved/unapproved callers before switching consumers.

Staff case routes continue to obtain a tenant/party/application-specific grant
from Decision Engine; they do not need blanket internal document privileges.
Ordinary tenant-scoped tokens retain their tenant/environment checks.

The retained legacy internal route is still a broad integration privilege within
one deployment. Prefer case-specific or tenant-scoped tokens for new integrations.
This change does not certify malware scanning or participant consent.
