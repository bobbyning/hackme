package poolfuzz

// Report 26 decision-time regression — after the sticky-claim fix, a forged
// upgrade injection is refused and DrainHuntReplayQueue finalizes the victim's
// clean shard as result_ok=1 (not fake_crash burial).

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hackme/internal/hunt"
	"hackme/internal/store"
)

func TestReport26DecisionKeepsCleanShardAfterInjectionAttempt(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang required for real harness replay")
	}
	t.Setenv("HACKME_POOL_HUNT_REPLAY", "1")
	t.Setenv("HACKME_POOL_HUNT_REPLAY_ASYNC", "1")

	ctx := context.Background()
	root := hunt.RepoRoot()
	hash, err := hunt.CatalogHarnessHash(root, "jsmn")
	if err != nil {
		t.Skip(err)
	}
	binPath, err := hunt.EnsureHarnessBinary(ctx, root, "jsmn", hash)
	if err != nil {
		t.Skipf("jsmn harness build unavailable: %v", err)
	}
	binBytes, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "r26d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := &Service{DB: db}

	cfg := map[string]any{
		"pool_distributed":     true,
		"work_kind":            "hunt_shard",
		"campaign_type":        "hunt",
		"upstream_target_id":   "jsmn",
		"harness_hash":         hash,
		"iterations_per_shard": 2,
		"max_input_bytes":      256,
		"depth_tier":           "oss_cve",
		"check_semantics":      "native_crash",
	}
	id := "r26-decision"
	if err := svc.RegisterCampaign(ctx, Campaign{ID: id, CampaignType: "hunt", Status: "running", BudgetRuns: 1, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	hunt.SetHarnessObjectDir("")
	t.Cleanup(func() { hunt.SetHarnessObjectDir("") })
	if err := hunt.PutHarnessArtifact(ctx, db, hash, binBytes, "jsmn"); err != nil {
		t.Fatal(err)
	}
	_ = svc.EnsureWorkItems(ctx, id, time.Now().Unix())
	w, ok, err := svc.Claim(ctx, "victim-w1", time.Now().Unix())
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}

	itemState := func() (st string, okFlag int, lastErr string) {
		err := db.QueryRowContext(ctx,
			`SELECT status, COALESCE(result_ok,0), COALESCE(last_error,'') FROM fuzz_work_items WHERE campaign_id=? AND id=?`,
			id, w.ItemID).Scan(&st, &okFlag, &lastErr)
		if err != nil {
			t.Fatal(err)
		}
		return
	}

	victim := SubmitRequest{
		WorkerID: "victim-w1", WorkID: w.WorkID, CampaignID: w.CampaignID,
		ItemID: w.ItemID, InputN: w.InputN, ActualInput: w.ActualInput, InputBytes: w.InputBytes,
		CheckResult: 0, Trap: "", DurationMS: 9, SegmentExecDone: 2,
	}
	if _, err := svc.SubmitWithOutcome(ctx, victim); err != nil {
		t.Fatal(err)
	}

	poison := victim
	poison.CheckResult = 1
	poison.Trap = "hunt_crash:heap-buffer-overflow"
	_, err = svc.SubmitWithOutcome(ctx, poison)
	if err == nil || !strings.Contains(err.Error(), "refuse claim change") {
		t.Fatalf("injection must be refused, got %v", err)
	}

	if err := svc.DrainHuntReplayQueue(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	st, okFlag, lastErr := itemState()
	if st != "done" {
		t.Fatalf("item status after drain: %q", st)
	}
	if okFlag != 1 {
		t.Fatalf("clean shard must pass result_ok=1, got %d last_error=%q", okFlag, lastErr)
	}
	if strings.Contains(lastErr, "fake_crash") {
		t.Fatalf("must not attribute fake_crash, got %q", lastErr)
	}

	var summary string
	if err := db.QueryRowContext(ctx, `SELECT summary_json FROM fuzz_campaigns WHERE id=?`, id).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary, `"failed_checks":1`) || strings.Contains(summary, `"failed_checks": 1`) {
		t.Fatalf("failed_checks must not be 1 after refused injection, summary=%s", summary)
	}
}
