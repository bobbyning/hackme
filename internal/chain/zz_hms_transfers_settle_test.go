package chain

// HMS transfer settlement regression tests.
//
// On main, applyPendingHmsTransfers has zero call sites, so accepted HMS
// transfers stay pending forever (the endpoint returns a tx hash and the
// pool is never drained), and ValidateHmsTransferShape does not reject
// From == To. These tests pin the fixed behavior: transfers settle on the
// next PoH block (same as the HMC and SUP lanes) and self-sends are
// rejected at submit (parity with the HMC lane and the report #30 SUP fix).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"hackme/internal/store"
)

func hmsSettleWallet(t *testing.T) (*Service, string, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "hms-settle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := New(db)
	if _, _, err := svc.InitGenesis(ctx, "HMC-node"); err != nil {
		t.Fatal(err)
	}
	if err := svc.InitHMSGenesis(ctx, "HMC-aaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := addressFromPubKeyHex(hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	if code, err := svc.MintHMS(ctx, addr, HMSToUnits(5.0), "fund"); err != nil || code != "" {
		t.Fatalf("MintHMS: code=%q err=%v", code, err)
	}
	return svc, addr, priv
}

func hmsSettleTx(t *testing.T, svc *Service, from, to string, amount, nonce uint64, priv ed25519.PrivateKey) HmsTransferTx {
	t.Helper()
	tx := HmsTransferTx{
		TxType:        "transfer_hms_v1",
		From:          from,
		To:            to,
		AmountUnits:   amount,
		FeeUnits:      DefaultHMSTransferMinFee,
		Nonce:         nonce,
		TimestampUnix: time.Now().Unix(),
		PubKeyEd25519: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}
	b, err := tx.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	tx.SigEd25519 = hex.EncodeToString(ed25519.Sign(priv, b))
	return tx
}

func hmsSettleAppendBlock(t *testing.T, svc *Service) {
	t.Helper()
	ctx := context.Background()
	m, err := svc.PoHTargetMod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, e := firstPoHHit(m)
	if _, err := svc.AppendPoHBlock(ctx, "HMC-node", n, e, 0, m, ""); err != nil {
		t.Fatal(err)
	}
}

func TestHMSTransferSettlesOnBlockAppend(t *testing.T) {
	ctx := context.Background()
	svc, addrA, privA := hmsSettleWallet(t)
	const toB = "HMC-cccccccccccccccc"
	tx := hmsSettleTx(t, svc, addrA, toB, HMSToUnits(1.0), 0, privA)
	txHash, st, err := svc.SubmitHmsTransferTx(ctx, tx)
	if err != nil || st != "pending" {
		t.Fatalf("submit: st=%q err=%v", st, err)
	}
	hmsSettleAppendBlock(t, svc)

	var pending int
	if err := svc.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hms_tx_pool WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("block applied but HMS pool not drained: pending=%d", pending)
	}
	stB, err := svc.HmsAddressState(ctx, toB)
	if err != nil || stB.BalanceHMSUnits != HMSToUnits(1.0) {
		t.Fatalf("recipient not credited: units=%d err=%v", stB.BalanceHMSUnits, err)
	}
	stA, err := svc.HmsAddressState(ctx, addrA)
	if err != nil {
		t.Fatal(err)
	}
	want := HMSToUnits(5.0) - HMSToUnits(1.0) - DefaultHMSTransferMinFee
	if stA.BalanceHMSUnits != want {
		t.Fatalf("sender balance: got %d want %d (amount+fee debited once)", stA.BalanceHMSUnits, want)
	}
	if stA.HMSNextNonce != 1 {
		t.Fatalf("sender nonce: got %d want 1", stA.HMSNextNonce)
	}
	var hist int
	if err := svc.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hms_tx_history WHERE tx_hash=? AND status='included'`, txHash).Scan(&hist); err != nil {
		t.Fatal(err)
	}
	if hist != 1 {
		t.Fatalf("included history rows for the settled tx: got %d want 1", hist)
	}
}

func TestHMSSelfTransferRejectedAtSubmit(t *testing.T) {
	ctx := context.Background()
	svc, addrA, privA := hmsSettleWallet(t)
	tx := hmsSettleTx(t, svc, addrA, addrA, HMSToUnits(4.0), 0, privA)
	hash, st, err := svc.SubmitHmsTransferTx(ctx, tx)
	if st != "invalid_address" || err == nil {
		t.Fatalf("self-send must be rejected with invalid_address: st=%q hash=%q err=%v", st, hash, err)
	}
	var cnt int
	if err := svc.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hms_tx_pool`).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("self-send must not enter the pool: rows=%d", cnt)
	}
}
