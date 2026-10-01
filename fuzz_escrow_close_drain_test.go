package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"hackme/internal/chain"
	"hackme/internal/store"
)

// Report #23: progress-path close must not finalize/cancel when settle pull
// cannot drain (worker-token-only / silent no-op). Escrow stays open so queued
// pays remain payable after ops restores the admin token.
func TestReport23RefuseCloseWhenSettlePullCannotDrain(t *testing.T) {
	t.Setenv("HACKME_POOL_COORDINATOR_URL", "http://127.0.0.1:19099")
	t.Setenv("HACKME_COORDINATOR_ADMIN_TOKEN", "")
	t.Setenv("HACKME_POOL_COORDINATOR_ADMIN_TOKEN", "")
	t.Setenv("HACKME_POOL_COORDINATOR_TOKEN", "worker-only")

	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "r23.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := chain.New(db)
	payer := "HMC-1111111111111111"
	if _, _, err := svc.InitGenesis(ctx, payer); err != nil {
		t.Fatal(err)
	}
	preFundMainEscrow(t, ctx, db, payer, 50)
	const camp = "r23-refuse"
	if _, err := svc.OpenFuzzEscrow(ctx, camp, 10.0, 100); err != nil {
		t.Fatal(err)
	}
	a := &app{chain: svc}

	walletBefore := walletUnits(t, db)
	a.tryCloseFuzzEscrowForStatus(ctx, camp, "completed")
	row, err := svc.GetFuzzEscrow(ctx, camp)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "open" && row.Status != "bounty_paid" {
		t.Fatalf("completed without drain closed escrow status=%q; want still open", row.Status)
	}
	if walletUnits(t, db) != walletBefore {
		t.Fatalf("wallet changed on refused finalize: before=%d after=%d", walletBefore, walletUnits(t, db))
	}

	a.tryCloseFuzzEscrowForStatus(ctx, camp, "cancelled")
	row, err = svc.GetFuzzEscrow(ctx, camp)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status == "closed" {
		t.Fatal("cancelled without drain closed escrow; want refuse")
	}
	if walletUnits(t, db) != walletBefore {
		t.Fatalf("wallet changed on refused cancel: before=%d after=%d", walletBefore, walletUnits(t, db))
	}
}

func walletUnits(t *testing.T, db *sql.DB) uint64 {
	t.Helper()
	var u uint64
	if err := db.QueryRow(`SELECT balance_units FROM wallet WHERE id=1`).Scan(&u); err != nil {
		t.Fatal(err)
	}
	return u
}
