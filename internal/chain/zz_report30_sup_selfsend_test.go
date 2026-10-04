package chain

// Report #30: SUP self-transfer must not mint (parity with HMC lane).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestReport30SupSelfTransferRejected(t *testing.T) {
	ctx := context.Background()
	svc, addrA, privA, _ := supTestWallet(t)
	pubA := privA.Public().(ed25519.PublicKey)
	tx := SupTransferTx{
		TxType:        "transfer_sup_v1",
		From:          addrA,
		To:            addrA,
		AmountUnits:   SUPToUnits(4.0),
		FeeUnits:      DefaultSUPTransferMinFee,
		Nonce:         0,
		TimestampUnix: time.Now().Unix(),
		PubKeyEd25519: hex.EncodeToString(pubA),
	}
	tx = signSupTransfer(t, tx, privA)
	_, code, err := svc.SubmitSupTransferTx(ctx, tx)
	if err == nil || code != "invalid_address" {
		t.Fatalf("self-send must be rejected: code=%q err=%v", code, err)
	}
	st, err := svc.SupAddressState(ctx, addrA)
	if err != nil {
		t.Fatal(err)
	}
	if st.BalanceSUPUnits != SUPToUnits(5.0) {
		t.Fatalf("balance must stay 5.0 SUP, got %d", st.BalanceSUPUnits)
	}
	if st.SUPNextNonce != 0 {
		t.Fatalf("nonce must stay 0, got %d", st.SUPNextNonce)
	}
}

func TestReport30ValidateSupTransferShapeRejectsSelf(t *testing.T) {
	code, _ := ValidateSupTransferShape(SupTransferTx{
		TxType:      "transfer_sup_v1",
		From:        "HMC-aaaaaaaaaaaaaaaa",
		To:          "HMC-aaaaaaaaaaaaaaaa",
		AmountUnits: 1,
		FeeUnits:    DefaultSUPTransferMinFee,
	})
	if code != "invalid_address" {
		t.Fatalf("shape must reject From==To, got %q", code)
	}
}

func TestReport30PooledSelfSendRejectedOnApplyNoMint(t *testing.T) {
	// If a self-send is already sitting in the pool, apply must reject it (not mint).
	ctx := context.Background()
	svc, addrA, privA, _ := supTestWallet(t)
	pubA := privA.Public().(ed25519.PublicKey)
	tx := SupTransferTx{
		TxType:        "transfer_sup_v1",
		From:          addrA,
		To:            addrA,
		AmountUnits:   SUPToUnits(1.0),
		FeeUnits:      DefaultSUPTransferMinFee,
		Nonce:         0,
		TimestampUnix: time.Now().Unix(),
		PubKeyEd25519: hex.EncodeToString(pubA),
	}
	tx = signSupTransfer(t, tx, privA)
	txHash, err := tx.HashHex()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.ExecContext(ctx,
		`INSERT INTO sup_tx_pool (tx_hash, tx_json, from_address, to_address, nonce, fee_units, amount_units, received_at, status, reject_code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', '')`,
		txHash, string(raw), tx.From, tx.To, tx.Nonce, tx.FeeUnits, tx.AmountUnits, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	before, err := svc.SupAddressState(ctx, addrA)
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.PoHTargetMod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, e := firstPoHHit(m)
	if _, err := svc.AppendPoHBlock(ctx, "HMC-node", n, e, 0, m, ""); err != nil {
		t.Fatal(err)
	}
	after, err := svc.SupAddressState(ctx, addrA)
	if err != nil {
		t.Fatal(err)
	}
	if after.BalanceSUPUnits != before.BalanceSUPUnits {
		t.Fatalf("apply must not mint on pooled self-send: before=%d after=%d", before.BalanceSUPUnits, after.BalanceSUPUnits)
	}
	var st string
	err = svc.db.QueryRowContext(ctx, `SELECT status FROM sup_tx_history WHERE tx_hash=?`, txHash).Scan(&st)
	if err != nil || st != "rejected" {
		t.Fatalf("pooled self-send must land as rejected history, status=%q err=%v", st, err)
	}
}
