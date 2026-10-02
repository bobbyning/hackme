package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"hackme/internal/fuzzengine"
	"hackme/internal/fuzzingcli"
)

// requireSecurityWasm skips tests that depend on the rust/wasm toolchain pack when
// the artifact has not been built AND rustc is unavailable, so a Go-only checkout
// gets a clear signal instead of hard failures (same convention as internal/sandbox
// and tools/fluxtap_wasm_compare). With rustc on PATH the pre-existing behavior is
// kept: pack tests self-build via buildPackWasm, explicit-path tests fail loudly.
func requireSecurityWasm(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "tasks", "artifacts", "security", name)
	if _, err := os.Stat(p); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cannot stat security wasm %s: %v", name, err)
		}
		if _, lerr := exec.LookPath("rustc"); lerr != nil {
			t.Skipf("security wasm %s not built and rustc unavailable (run scripts/build_security_task_pack.sh; toolchain: docs/RUST_CPP_TASKS_QUICKSTART.md): %v", name, err)
		}
	}
	return p
}

func TestWizardRefusesPublicBase(t *testing.T) {
	if fuzzingcli.IsLoopbackBase("https://hackme.tech") {
		t.Fatal("hackme.tech must not be loopback")
	}
	// Report #24: userinfo bypass of the wizard gate.
	if fuzzingcli.IsLoopbackBase("http://127.0.0.1:8080@evil.example") {
		t.Fatal("userinfo spoof must not pass wizard loopback gate")
	}
}

func TestWizardDryRunScanPackage(t *testing.T) {
	wasm := requireSecurityWasm(t, "rust_script_push_bounds_guard.wasm")
	m, err := doWizardDryRun("scan", wasm)
	if err != nil {
		t.Fatal(err)
	}
	if m["depth_tier"] != "wasm_only" {
		t.Fatalf("depth_tier=%v", m["depth_tier"])
	}
	if m["pool_distributed"] != false {
		t.Fatalf("scan should be local pool_distributed=false")
	}
	if m["create_poh_order"] != false {
		t.Fatalf("scan should not create PoH")
	}
	sigs, _ := m["signal_types"].([]string)
	if len(sigs) == 0 || sigs[0] != "wasm_smoke" {
		t.Fatalf("scan signals=%v", m["signal_types"])
	}
}

func TestWizardDryRunPackSecrets(t *testing.T) {
	requireSecurityWasm(t, "rust_tracefuse_detector_bytes_guard.wasm")
	m, err := doWizardDryRunPack("audit", "secrets", "")
	if err != nil {
		t.Fatal(err)
	}
	if m["pack"] != "secrets" {
		t.Fatalf("pack=%v", m["pack"])
	}
	if m["input_mode"] != "bytes" {
		t.Fatalf("input_mode=%v", m["input_mode"])
	}
	if m["guided_scheduling"] != true {
		t.Fatal("expected guided")
	}
	if m["depth_tier"] != string(fuzzengine.DepthBytesCorpus) {
		t.Fatalf("depth_tier=%v", m["depth_tier"])
	}
	if m["wasm_len"].(int) < 100 {
		t.Fatalf("wasm too small: %v", m["wasm_len"])
	}
}

func TestWizardDryRunPackagesDiffer(t *testing.T) {
	wasm := requireSecurityWasm(t, "rust_script_push_bounds_guard.wasm")
	scan, err := doWizardDryRun("scan", wasm)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := doWizardDryRun("audit", wasm)
	if err != nil {
		t.Fatal(err)
	}
	deep, err := doWizardDryRun("deep", wasm)
	if err != nil {
		t.Fatal(err)
	}
	if scan["depth_tier"] == audit["depth_tier"] || audit["depth_tier"] == deep["depth_tier"] {
		t.Fatalf("tiers must differ: scan=%v audit=%v deep=%v", scan["depth_tier"], audit["depth_tier"], deep["depth_tier"])
	}
	if deep["depth_tier"] != string(fuzzengine.DepthBytesCorpus) {
		t.Fatalf("deep depth_tier=%v", deep["depth_tier"])
	}
	if deep["budget_runs"].(int) <= audit["budget_runs"].(int) {
		t.Fatalf("deep runs must exceed audit: deep=%v audit=%v", deep["budget_runs"], audit["budget_runs"])
	}
	if deep["budget_seconds"].(int) < 3600*8 {
		t.Fatalf("deep should be hours-scale budget_seconds, got %v", deep["budget_seconds"])
	}
	if deep["mutation_rounds"].(int) < 8 {
		t.Fatalf("deep should use heavy mutation, got %v", deep["mutation_rounds"])
	}
	if deep["coverage_guided"] != true {
		t.Fatal("deep should be coverage_guided")
	}
	if cap, ok := deep["power_mut_cap"].(int); !ok || cap < 10 {
		t.Fatalf("deep power_mut_cap=%v", deep["power_mut_cap"])
	}
	deepSigs, _ := deep["signal_types"].([]string)
	auditSigs, _ := audit["signal_types"].([]string)
	if len(deepSigs) <= len(auditSigs) {
		t.Fatalf("deep signals should exceed audit: deep=%v audit=%v", deepSigs, auditSigs)
	}
}
