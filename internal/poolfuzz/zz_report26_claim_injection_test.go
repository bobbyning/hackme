package poolfuzz

// Report 26 — after #25 (weaken-only), forged worker_id could still UPGRADE a
// pending clean claim to hunt_crash, lock the victim out of repair, and bury
// clean work as fake_crash. Fix: refuse ANY claim change on pending/processing
// (idempotent re-submit only) + sticky SQL claim columns.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hackme/internal/hunt"
	"hackme/internal/store"
)

func setupR26(t *testing.T) (*Service, string, ClaimedWork, func()) {
	t.Helper()
	t.Setenv("HACKME_POOL_HUNT_REPLAY", "1")
	t.Setenv("HACKME_POOL_HUNT_REPLAY_ASYNC", "1")

	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "r26.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db}
	ctx := context.Background()

	cfg := map[string]any{
		"pool_distributed":     true,
		"work_kind":            "hunt_shard",
		"campaign_type":        "hunt",
		"upstream_target_id":   "jsmn",
		"harness_hash":         "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"iterations_per_shard": 2,
		"max_input_bytes":      256,
		"depth_tier":           "oss_cve",
		"check_semantics":      "native_crash",
	}
	id := "r26-camp"
	if err := svc.RegisterCampaign(ctx, Campaign{ID: id, CampaignType: "hunt", Status: "running", BudgetRuns: 1, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	hunt.SetHarnessObjectDir("")
	if err := hunt.PutHarnessArtifact(ctx, db, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", []byte("poc26-harness-blob"), "jsmn"); err != nil {
		t.Fatal(err)
	}
	_ = svc.EnsureWorkItems(ctx, id, time.Now().Unix())
	w, ok, err := svc.Claim(ctx, "victim-w1", time.Now().Unix())
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	return svc, id, w, func() { hunt.SetHarnessObjectDir(""); db.Close() }
}

func qrow26(ctx context.Context, t *testing.T, svc *Service, id string, item int64) (string, int32, string, string) {
	t.Helper()
	var wid string
	var cr int32
	var trap, st string
	err := svc.DB.QueryRowContext(ctx,
		`SELECT COALESCE(worker_id,''), COALESCE(worker_check_result,0), COALESCE(worker_trap,''), status
		 FROM fuzz_hunt_replay_queue WHERE campaign_id=? AND item_id=?`, id, item).
		Scan(&wid, &cr, &trap, &st)
	if err != nil {
		t.Fatal(err)
	}
	return wid, cr, trap, st
}

func TestReport26ClaimInjectionRefused(t *testing.T) {
	svc, id, w, done := setupR26(t)
	defer done()
	ctx := context.Background()

	clean := SubmitRequest{
		WorkerID: "victim-w1", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 0, Trap: "", DurationMS: 9, SegmentExecDone: 2,
	}
	out, err := svc.SubmitWithOutcome(ctx, clean)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Async || out.ReplayStatus != huntReplayStatusPending {
		t.Fatalf("victim submit: %+v", out)
	}
	wid, cr, trap, st := qrow26(ctx, t, svc, id, w.ItemID)
	if wid != "victim-w1" || cr != 0 || trap != "" || st != "pending" {
		t.Fatalf("victim row: wid=%q cr=%d trap=%q st=%q", wid, cr, trap, st)
	}

	// ATTACK must be refused (was accepted before #26).
	poison := clean
	poison.CheckResult = 1
	poison.Trap = "hunt_crash:poisoned-by-attacker"
	_, err = svc.SubmitWithOutcome(ctx, poison)
	if err == nil || !strings.Contains(err.Error(), "refuse claim change") {
		t.Fatalf("upgrade injection must be refused, got %v", err)
	}
	wid, cr, trap, st = qrow26(ctx, t, svc, id, w.ItemID)
	if wid != "victim-w1" || cr != 0 || trap != "" || st != "pending" {
		t.Fatalf("clean claim must survive: wid=%q cr=%d trap=%q st=%q", wid, cr, trap, st)
	}

	// Idempotent clean re-submit still OK.
	out2, err := svc.SubmitWithOutcome(ctx, clean)
	if err != nil || !out2.Async {
		t.Fatalf("idempotent clean retry: err=%v out=%+v", err, out2)
	}

	// CONTROL: downgrade also refused (symmetric sticky claim).
	if _, err := svc.DB.ExecContext(ctx,
		`UPDATE fuzz_hunt_replay_queue SET worker_check_result=?, worker_trap=? WHERE campaign_id=? AND item_id=?`,
		1, "hunt_crash:x", id, w.ItemID); err != nil {
		t.Fatal(err)
	}
	down := clean
	_, err = svc.SubmitWithOutcome(ctx, down)
	if err == nil || !strings.Contains(err.Error(), "refuse claim change") {
		t.Fatalf("downgrade must be refused, got %v", err)
	}
}

func TestReport26SanitizerToCrashUpgradeRefused(t *testing.T) {
	svc, id, w, done := setupR26(t)
	defer done()
	ctx := context.Background()

	san := SubmitRequest{
		WorkerID: "victim-w1", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 1, Trap: "hunt_sanitizer:unsigned-integer-overflow", DurationMS: 9, SegmentExecDone: 2,
	}
	if _, err := svc.SubmitWithOutcome(ctx, san); err != nil {
		t.Fatal(err)
	}
	upgrade := san
	upgrade.Trap = "hunt_crash:heap-buffer-overflow"
	_, err := svc.SubmitWithOutcome(ctx, upgrade)
	if err == nil || !strings.Contains(err.Error(), "refuse claim change") {
		t.Fatalf("sanitizer→crash upgrade must be refused, got %v", err)
	}
	_, cr, trap, _ := qrow26(ctx, t, svc, id, w.ItemID)
	if cr != 1 || trap != "hunt_sanitizer:unsigned-integer-overflow" {
		t.Fatalf("sanitizer claim must stick: cr=%d trap=%q", cr, trap)
	}
}

func TestReport26PreemptivePoisonLocksVictimUntilAuthLayer(t *testing.T) {
	// Service-level first writer still owns the claim (forged worker_id == lease owner).
	// Coordinator submit lock (Report #26 class fix) closes this when worker_id is
	// payout-locked from claim-time PoP. Here we assert sticky anti-repair after poison.
	svc, id, w, done := setupR26(t)
	defer done()
	ctx := context.Background()

	pre := SubmitRequest{
		WorkerID: "victim-w1", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 1, Trap: "hunt_crash:preemptive-poison", DurationMS: 1, SegmentExecDone: 2,
	}
	if _, err := svc.SubmitWithOutcome(ctx, pre); err != nil {
		t.Fatalf("preemptive first-writer: %v", err)
	}
	wid, cr, trap, _ := qrow26(ctx, t, svc, id, w.ItemID)
	if wid != "victim-w1" || cr != 1 || trap != "hunt_crash:preemptive-poison" {
		t.Fatalf("preemptive row: wid=%q cr=%d trap=%q", wid, cr, trap)
	}
	victim := pre
	victim.CheckResult = 0
	victim.Trap = ""
	if _, err := svc.SubmitWithOutcome(ctx, victim); err == nil || !strings.Contains(err.Error(), "refuse claim change") {
		t.Fatalf("after preemptive poison clean repair must be refused, got %v", err)
	}
}
