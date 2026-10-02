package poolfuzz

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"hackme/internal/hunt"
	"hackme/internal/store"
)

// Claims for hunt campaigns whose cfg carries seed_byte_corpus must ship the
// corpus so worker-side exec input derivation matches the verification replay.
func TestClaimShipsSeedByteCorpus(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "r21.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := &Service{DB: db}
	ctx := context.Background()

	corpus := []any{"deadbeef01020304", "cafebabefeedface", "4142434445464748"}
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
		"seed_byte_corpus":     corpus,
	}
	id := "r21-camp"
	if err := svc.RegisterCampaign(ctx, Campaign{ID: id, CampaignType: "hunt", Status: "running", BudgetRuns: 1, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	hunt.SetHarnessObjectDir("")
	t.Cleanup(func() { hunt.SetHarnessObjectDir("") })
	if err := hunt.PutHarnessArtifact(ctx, db, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", []byte("r21-harness-blob"), "jsmn"); err != nil {
		t.Fatal(err)
	}
	_ = svc.EnsureWorkItems(ctx, id, time.Now().Unix())
	w, ok, err := svc.Claim(ctx, "w21", time.Now().Unix())
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if len(w.SeedByteCorpus) != len(corpus) {
		t.Fatalf("SeedByteCorpus not shipped: len=%d want %d", len(w.SeedByteCorpus), len(corpus))
	}
	for i := range corpus {
		if w.SeedByteCorpus[i] != corpus[i] {
			t.Fatalf("SeedByteCorpus[%d]=%v want %v", i, w.SeedByteCorpus[i], corpus[i])
		}
	}
}
