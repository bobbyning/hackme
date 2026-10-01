package poolfuzz

// Report 25 — forged worker_id on submit could rewrite a queued hunt_crash claim
// to clean (H-01 ownership guard keys on the self-declared id). Fix: refuse
// claim-weakening re-submits and keep processing rows from resetting to pending.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hackme/internal/hunt"
	"hackme/internal/store"
)

func TestReport25ForgedWorkerIDRewritesQueuedVerdict(t *testing.T) {
	t.Setenv("HACKME_POOL_HUNT_REPLAY", "1")
	t.Setenv("HACKME_POOL_HUNT_REPLAY_ASYNC", "1")

	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "r25.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
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
	id := "r25-camp"
	if err := svc.RegisterCampaign(ctx, Campaign{ID: id, CampaignType: "hunt", Status: "running", BudgetRuns: 1, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	hunt.SetHarnessObjectDir("")
	t.Cleanup(func() { hunt.SetHarnessObjectDir("") })
	if err := hunt.PutHarnessArtifact(ctx, db, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", []byte("poc25-harness-blob"), "jsmn"); err != nil {
		t.Fatal(err)
	}
	_ = svc.EnsureWorkItems(ctx, id, time.Now().Unix())
	w, ok, err := svc.Claim(ctx, "victim-w1", time.Now().Unix())
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}

	qrow := func() (wid string, cr int, trap, st string) {
		err := db.QueryRowContext(ctx,
			`SELECT COALESCE(worker_id,''), COALESCE(worker_check_result,0), COALESCE(worker_trap,''), status
			 FROM fuzz_hunt_replay_queue WHERE campaign_id=? AND item_id=?`, id, w.ItemID).
			Scan(&wid, &cr, &trap, &st)
		if err != nil {
			t.Fatal(err)
		}
		return
	}

	out, err := svc.SubmitWithOutcome(ctx, SubmitRequest{
		WorkerID: "victim-w1", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 1, Trap: "hunt_crash:heap-buffer-overflow", DurationMS: 9, SegmentExecDone: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Async || out.ReplayStatus != huntReplayStatusPending {
		t.Fatalf("victim submit: %+v", out)
	}
	wid, cr, trap, st := qrow()
	if wid != "victim-w1" || cr != 1 || trap != "hunt_crash:heap-buffer-overflow" || st != "pending" {
		t.Fatalf("victim row: wid=%q cr=%d trap=%q st=%q", wid, cr, trap, st)
	}

	clean := SubmitRequest{
		WorkerID: "", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 0, Trap: "", DurationMS: 1, SegmentExecDone: 2,
	}

	own := clean
	own.WorkerID = "attacker-w2"
	_, err = svc.SubmitWithOutcome(ctx, own)
	if err == nil || !strings.Contains(err.Error(), "already claimed by another worker") {
		t.Fatalf("control: expected hijack rejection, got %v", err)
	}

	forged := clean
	forged.WorkerID = "victim-w1"
	_, err = svc.SubmitWithOutcome(ctx, forged)
	if err == nil || !strings.Contains(err.Error(), "refuse claim weakening") {
		t.Fatalf("forged weaken must be rejected, got %v", err)
	}
	wid, cr, trap, st = qrow()
	if wid != "victim-w1" || cr != 1 || trap != "hunt_crash:heap-buffer-overflow" || st != "pending" {
		t.Fatalf("crash claim must survive forged rewrite: wid=%q cr=%d trap=%q st=%q", wid, cr, trap, st)
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE fuzz_hunt_replay_queue SET status='processing' WHERE campaign_id=? AND item_id=?`, id, w.ItemID); err != nil {
		t.Fatal(err)
	}
	forged2 := clean
	forged2.WorkerID = "victim-w1"
	_, err = svc.SubmitWithOutcome(ctx, forged2)
	if err == nil {
		t.Fatal("processing + weaken must be rejected")
	}
	_, _, _, st = qrow()
	if st != "processing" {
		t.Fatalf("processing row must not reset to pending: %q", st)
	}
}

func TestHuntClaimWouldWeaken(t *testing.T) {
	if !huntClaimWouldWeaken(1, "hunt_crash:x", 0, "") {
		t.Fatal("crash→clean must weaken")
	}
	if !huntClaimWouldWeaken(1, "hunt_crash:x", 1, "hunt_sanitizer:y") {
		t.Fatal("crash→sanitizer must weaken")
	}
	if huntClaimWouldWeaken(0, "", 1, "hunt_crash:x") {
		t.Fatal("clean→crash must not weaken")
	}
	if huntClaimWouldWeaken(1, "hunt_crash:x", 1, "hunt_crash:x") {
		t.Fatal("idempotent must not weaken")
	}
}
