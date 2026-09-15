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

Status: domain/storage methods and disposable-PostgreSQL isolation tests are
implemented. HTTP owner-grant resolution, routes and Payment Rails adapter
remain to be connected; no running deployment uses these new methods yet.
