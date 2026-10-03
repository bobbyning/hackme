package main

// Follow-up to report #29 (ee5f702): the stall easing only armed while no found
// had EVER been accepted since boot (lastFoundHitUnix > 0 -> return), so the
// realistic freeze shape - a running pool whose finds went silent later - was
// still uneased. These tests pin stale-found easing behavior.

import (
	"path/filepath"
	"testing"
)

func stallEaseWM(t *testing.T, mod uint64) *workManager {
	t.Helper()
	t.Setenv("HACKME_COORDINATOR_TARGET_MOD_FILE", filepath.Join(t.TempDir(), "coordinator_target_mod.txt"))
	return &workManager{
		targetMod:          mod,
		targetModMin:       2_000_000,
		targetModMax:       1_000_000_000,
		poolRetarget:       true,
		poolRetargetMinSec: 3,
		rewardAuto:         true,
		baseRewardHMC:      0.01,
		foundBonus:         0.01,
		rewardPerM:         1e-05,
	}
}

func TestStallEaseFiresAfterFoundWentStale(t *testing.T) {
	m := stallEaseWM(t, 5_000_003) // solvable but high
	now := int64(1_700_000_000)
	ago := now - 2*poolStallEaseFoundGapSec
	m.targetModUpdatedUnix = ago
	m.lastPoolRetargetUnix = ago
	m.lastFoundHitUnix = ago // running pool, finds went silent two gaps ago
	m.maybeEasePoolModOnStallLocked(now)
	if m.targetMod >= 5_000_003 {
		t.Fatalf("stale found must still ease M, got %d", m.targetMod)
	}
	if m.targetMod%7 == 0 {
		t.Fatalf("eased M must stay solvable, got %d", m.targetMod)
	}
}

func TestStallEaseSkipsFreshFound(t *testing.T) {
	m := stallEaseWM(t, 5_000_003)
	now := int64(1_700_000_000)
	ago := now - 2*poolStallEaseFoundGapSec
	m.targetModUpdatedUnix = ago
	m.lastPoolRetargetUnix = ago
	m.lastFoundHitUnix = now - 60 // found a minute ago: gate is solvable
	m.maybeEasePoolModOnStallLocked(now)
	if m.targetMod != 5_000_003 {
		t.Fatalf("fresh found must not ease M, got %d", m.targetMod)
	}
}

func TestStallEaseRespectsMStabilityWithStaleFound(t *testing.T) {
	m := stallEaseWM(t, 5_000_003)
	now := int64(1_700_000_000)
	m.targetModUpdatedUnix = now - 60 // M moved a minute ago
	m.lastPoolRetargetUnix = now - 60
	m.lastFoundHitUnix = now - 2*poolStallEaseFoundGapSec
	m.maybeEasePoolModOnStallLocked(now)
	if m.targetMod != 5_000_003 {
		t.Fatalf("recently-moved M must not ease even with stale found, got %d", m.targetMod)
	}
}
