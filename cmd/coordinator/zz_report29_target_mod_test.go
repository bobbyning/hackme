package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"hackme/internal/chain"
)

func report29WM(t *testing.T, mod uint64) *workManager {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HACKME_COORDINATOR_TARGET_MOD_FILE", filepath.Join(dir, "coordinator_target_mod.txt"))
	return &workManager{
		hybridSignerEnabled:    true,
		hybridSignerStrict:     true,
		hybridRequireFoundSig:  true,
		claimRequirePubKey:     true,
		claimPerMin:            200,
		submitPerMin:           600,
		maxActiveLeases:        500000,
		defaultBatch:           1 << 22,
		maxClaimBatch:          1 << 24,
		leaseSec:               90,
		maxWorkers:             200000,
		maxDedupEntries:        500000,
		targetMod:              mod,
		targetModMin:           2_000_000,
		targetModMax:           1_000_000_000,
		poolRetarget:           true,
		poolRetargetMinSec:     3,
		rewardAuto:             true,
		baseRewardHMC:          0.01,
		foundBonus:             0.01,
		rewardPerM:             1e-05,
		active:                 map[workKey]leaseRecord{},
		worker:                 map[string]workerPayoutStat{},
		acceptedResultHashes:   map[string]struct{}{},
		acceptedFoundNonces:    map[uint64]struct{}{},
		acceptedSubmitNonces:   map[string]struct{}{},
		acceptedSignedPayloads: map[string]struct{}{},
		signedSubmitNonceMax:   map[string]uint64{},
		abuse:                  map[string]workerAbuseState{},
		ipAbuse:                map[string]workerAbuseState{},
		dropReasonCount:        map[string]uint64{},
		supMeta:                map[string]workerSupMeta{},
	}
}

func TestReport29ClampSanitizesMod7(t *testing.T) {
	const bad = 2_100_000 // 7 | 2_100_000 — no solution for 7n+13
	if bad%7 != 0 {
		t.Fatal("precondition")
	}
	hits := 0
	for n := uint64(0); n < 2_000_000; n++ {
		if validFoundNonceV1(n, bad) {
			hits++
		}
	}
	if hits != 0 {
		t.Fatalf("7|M must have zero solutions, got %d", hits)
	}
	m := report29WM(t, bad)
	got := m.clampTargetMod(bad)
	if got == bad || got%7 == 0 {
		t.Fatalf("pool clampTargetMod must nudge off mod 7, got %d", got)
	}
	if chain.ClampPoHTargetMod(bad)%7 == 0 {
		t.Fatal("chain sanitizer sanity")
	}
	if sanitizePoolTargetMod7n13(bad, 2_000_000, 1_000_000_000)%7 == 0 {
		t.Fatal("sanitizePoolTargetMod7n13 must clear multiples of 7")
	}
}

func TestReport29LoadRetargetNeverPinsUnsolvable(t *testing.T) {
	m := report29WM(t, 2_000_000)
	now := int64(1_700_000_000)
	for i := 0; i < 40; i++ {
		now += m.poolRetargetMinSec + 1
		m.maybeRetargetPoolLoadLocked(now, 1.05, 1) // load hint ≈ 2_100_000
	}
	if m.targetMod%7 == 0 {
		t.Fatalf("load retarget must not freeze on unsolvable M, got %d", m.targetMod)
	}
	// Steady fleet must converge near the sanitized load target (2_100_001), not 2_100_000.
	if m.targetMod < 2_000_000 || m.targetMod > 2_200_000 {
		t.Fatalf("unexpected converged M=%d", m.targetMod)
	}
}

func TestReport29SanitizedModAcceptsFoundPay(t *testing.T) {
	m := report29WM(t, 2_100_000)
	m.targetMod = m.clampTargetMod(m.targetMod)
	if m.targetMod%7 == 0 {
		t.Fatalf("sanitized M still %%7==0: %d", m.targetMod)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	base, size, _, _, _, ok, reason := m.claim("rig-ok", 0)
	if !ok {
		t.Fatalf("claim: %s", reason)
	}
	var nonce uint64
	found := false
	for n := base; n < base+size; n++ {
		if validFoundNonceV1(n, m.targetMod) {
			nonce = n
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no valid nonce in lease for M=%d", m.targetMod)
	}
	req := submitWorkRequest{
		WorkerID: "rig-ok", BaseNonce: base, BatchSize: size,
		Found: true, HashrateGHS: 1.0, FoundNonce: nonce, ResultHash: "r29aa",
		Attempts: 1, SubmitNonce: 1,
		MinerPubKey: hex.EncodeToString(pub), MinerAddress: signerAddr(pub), MinerSigAlg: "ed25519",
	}
	req.MinerSig = hex.EncodeToString(ed25519.Sign(priv, canonicalSubmitBytes(req)))
	accepted, reason2, payout, _, _ := m.submit(req)
	if !accepted || reason2 != "" || payout < m.foundBonus {
		t.Fatalf("sanitized M must accept found: ok=%v reason=%s payout=%f", accepted, reason2, payout)
	}
}

func TestReport29PersistLoadSanitizes(t *testing.T) {
	report29WM(t, 2_100_000) // sets TARGET_MOD_FILE
	path := poolTargetModPersistPath()
	if err := os.WriteFile(path, []byte("2100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadPersistedPoolTargetMod()
	if got == 2_100_000 || got%7 == 0 {
		t.Fatalf("load must sanitize persisted unsolvable M, got %d", got)
	}
	persistPoolTargetMod(2_100_000)
	got2 := loadPersistedPoolTargetMod()
	if got2%7 == 0 {
		t.Fatalf("persist+load must stay solvable, got %d", got2)
	}
}

func TestReport29StallEasingWithoutFound(t *testing.T) {
	m := report29WM(t, 5_000_003) // solvable but high
	now := int64(1_700_000_000)
	m.targetModUpdatedUnix = now
	m.lastPoolRetargetUnix = now
	// Before stall window: no move.
	m.maybeEasePoolModOnStallLocked(now + chain.PoHRetargetTargetSec*3)
	if m.targetMod != 5_000_003 {
		t.Fatalf("must not ease before stall window, got %d", m.targetMod)
	}
	// After stall window: ease down without any accepted found.
	m.maybeEasePoolModOnStallLocked(now + chain.PoHRetargetTargetSec*6 + 1)
	if m.targetMod >= 5_000_003 || m.targetMod%7 == 0 {
		t.Fatalf("stall easing without found must lower M and stay solvable, got %d", m.targetMod)
	}
}
