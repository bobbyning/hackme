package workerfuzzloop

import (
	"bytes"
	"testing"

	"hackme/internal/hunt"
)

// The worker rebuilds its exec-derivation cfg from the claim JSON; it must stay
// byte-identical to the coordinator's verification replay cfg when the campaign
// ships a seed_byte_corpus (LF-imported seeds or pack byte seeds).
func TestHuntShardSeedByteCorpusParity(t *testing.T) {
	corpus := []any{"deadbeef01020304", "cafebabefeedface", "4142434445464748494a"}
	cr := ClaimResp{
		UpstreamTargetID: "jsmn",
		MaxInputBytes:    256,
		ExecPerUnit:      8,
		DepthTier:        "oss_cve",
		SeedByteCorpus:   corpus,
	}
	worker := huntShardConfigFromClaim(cr, false)

	replay := map[string]any{
		"upstream_target_id":   "jsmn",
		"max_input_bytes":      256,
		"input_mode":           "bytes",
		"iterations_per_shard": 8,
		"depth_tier":           "oss_cve",
		"seed_byte_corpus":     corpus,
	}
	hunt.ApplyHuntMutatorDict(replay, "jsmn") // registration normalizes the dict into campaign cfg

	for _, inputN := range []uint64{1, 2, 9} {
		for _, exec := range []uint64{1, 2, 3, 7, 19, 20} {
			want := hunt.ShardSegmentExecInput("parity-camp", inputN, exec, replay, nil)
			got := hunt.ShardSegmentExecInput("parity-camp", inputN, exec, worker, nil)
			if !bytes.Equal(want, got) {
				t.Fatalf("inputN=%d exec=%d: replay %d bytes vs worker %d bytes", inputN, exec, len(want), len(got))
			}
		}
	}
}

// Plain campaigns without a corpus keep the anchor fallback on both sides.
func TestHuntShardNoCorpusParity(t *testing.T) {
	cr := ClaimResp{
		UpstreamTargetID: "jsmn",
		MaxInputBytes:    256,
		ExecPerUnit:      8,
		DepthTier:        "oss_cve",
	}
	worker := huntShardConfigFromClaim(cr, false)
	replay := map[string]any{
		"upstream_target_id":   "jsmn",
		"max_input_bytes":      256,
		"input_mode":           "bytes",
		"iterations_per_shard": 8,
		"depth_tier":           "oss_cve",
	}
	hunt.ApplyHuntMutatorDict(replay, "jsmn")
	for _, inputN := range []uint64{1, 5} {
		for _, exec := range []uint64{1, 4, 19} {
			want := hunt.ShardSegmentExecInput("parity-camp", inputN, exec, replay, nil)
			got := hunt.ShardSegmentExecInput("parity-camp", inputN, exec, worker, nil)
			if !bytes.Equal(want, got) {
				t.Fatalf("inputN=%d exec=%d diverged without corpus", inputN, exec)
			}
		}
	}
}
