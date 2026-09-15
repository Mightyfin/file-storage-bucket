package documents

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type paymentQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Restrict payment receipts even when callers know the ID and have ordinary
// documents.read scope for the same tenant. Use the caller's transaction when
// checking evidence, so the check and its audit share the row lock.
func checkPaymentAccess(ctx context.Context, q paymentQuery, sc Scope, d Document) error {
	if d.Purpose == "bank_account_verification" {
		if !validBankAccountScope(sc) || d.OwnerID != sc.BankAccountOwnerID || d.OwnerType != sc.BankAccountOwnerType {
			return ErrNotFound
		}
		var found bool
		err := q.QueryRow(ctx, `SELECT true FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND source_reference=$4 AND owner_type=$5 AND owner_id=$6`, d.ID, sc.TenantID, sc.Environment, sc.BankAccountReference, sc.BankAccountOwnerType, sc.BankAccountOwnerID).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if d.Purpose != "manual_bank_payment" && d.Purpose != "manual_bank_statement" {
		return nil
	}
	reference := sc.PaymentReference
	if d.Purpose == "manual_bank_statement" {
		reference = sc.StatementReference
	}
	if reference == "" || sc.TenantID == "" || sc.Environment == "" {
		return ErrNotFound
	}
	var found bool
	err := q.QueryRow(ctx, `SELECT true FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND source_reference=$4`, d.ID, sc.TenantID, sc.Environment, reference).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
