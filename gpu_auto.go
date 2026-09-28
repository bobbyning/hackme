package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"hackme/internal/gpuhost"
	"hackme/internal/gputune"
)

func hostGPUInventory() gpuhost.HostGPUReport {
	return gpuhost.DetectHostGPUs()
}

func nvidiaSMILinesOK() bool {
	out, err := exec.Command("nvidia-smi", "-L").CombinedOutput()
	if err != nil {
		return false
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "driver/library version mismatch") || strings.Contains(s, "failed to initialize nvml") {
		return false
	}
	return len(out) > 0
}

// resolveAutoGPUBackend picks cuda vs opencl vs cpu from host hardware (Stage 1 — no manual vendor flag).
func resolveAutoGPUBackend(repoRoot string) string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("HACKME_GPU_DISABLE")), "1") {
		return "cpu"
	}
	if b := strings.TrimSpace(os.Getenv("HACKME_GPU_BACKEND")); b != "" && !strings.EqualFold(b, "auto") {
		return b
	}
	rep := hostGPUInventory()
	cudaBin, oclBin := gpuhost.ProbeWorkerBins(repoRoot)
	if runtime.GOOS == "windows" {
		// Only treat OpenCL as available when the ICD/runtime DLL exists. Shipping
		// workerpoh-opencl.exe in the installer is not enough (VBox/VMs often have
		// a virtual display adapter but no OpenCL.dll → instant worker crash).
		if oclBin && !windowsOpenCLRuntimePresent() {
			oclBin = false
		}
	}
	backend := gpuhost.ResolveBackend(gpuhost.BackendChoiceInput{
		Report:           rep,
		RepoRoot:         repoRoot,
		ForceOpenCL:      envTruthyGPU("HACKME_FORCE_OPENCL"),
		GPUDisabled:      false,
		HasCUDAWorkerBin: cudaBin,
		HasOCLWorkerBin:  oclBin,
		NVIDIASMIOK:      nvidiaSMILinesOK() || len(queryNVIDIAMulti()) > 0 || len(gpuhost.ListNVIDIAProcCards()) > 0,
	})
	return backend
}

func windowsOpenCLRuntimePresent() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	for _, p := range []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenCL.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "SysWOW64", "OpenCL.dll"),
	} {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func envTruthyGPU(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func enrichHostReportWithProfile(rep gpuhost.HostGPUReport) gpuhost.HostGPUReport {
	if p, ok := gputune.DetectRigProfile(rep.Names); ok {
		rep.SuggestedProfileID = p.ID
		if b := strings.TrimSpace(p.Env["HACKME_GPU_BACKEND"]); b != "" && !strings.EqualFold(b, "auto") {
			// Profile env is a hint; ResolveBackend already ran for worker start.
			if rep.SuggestedBackend == "" || rep.SuggestedBackend == "cpu" {
				rep.SuggestedBackend = b
			}
		}
	}
	if rep.SuggestedBackend == "" {
		rep.SuggestedBackend = resolveAutoGPUBackend(resolveWorkerRepoRoot(""))
	}
	return rep
}
