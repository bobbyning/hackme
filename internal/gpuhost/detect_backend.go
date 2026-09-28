package gpuhost

import (
	"os"
	"path/filepath"
	"strings"
)

// BackendChoiceInput is host inventory plus optional worker binary paths.
type BackendChoiceInput struct {
	Report           HostGPUReport
	RepoRoot         string
	ForceOpenCL      bool
	GPUDisabled      bool
	HasCUDAWorkerBin bool
	HasOCLWorkerBin  bool
	NVIDIASMIOK      bool
}

// ResolveBackend picks cuda | opencl | cpu from host GPUs and available worker binaries.
func ResolveBackend(in BackendChoiceInput) string {
	if in.GPUDisabled {
		return "cpu"
	}
	if in.ForceOpenCL {
		if in.HasOCLWorkerBin {
			return "opencl"
		}
		return "cpu"
	}
	rep := in.Report
	// Drop VM display adapters so VirtualBox/Hyper-V do not look like "a GPU".
	filtered := make([]string, 0, len(rep.Names))
	for _, n := range rep.Names {
		if !isVirtualDisplayAdapter(n) {
			filtered = append(filtered, n)
		}
	}
	rep.Names = filtered
	if !rep.HasNVIDIA && !rep.HasAMD && !rep.HasIntel && len(rep.Names) == 0 {
		return "cpu"
	}
	if rep.HasNVIDIA {
		if in.HasCUDAWorkerBin && in.NVIDIASMIOK {
			return "cuda"
		}
		// NVIDIA without working CUDA: OpenCL only when the OpenCL worker binary exists.
		if in.HasOCLWorkerBin {
			return "opencl"
		}
		return "cpu"
	}
	if rep.HasAMD || rep.HasIntel {
		if in.HasOCLWorkerBin {
			return "opencl"
		}
		return "cpu"
	}
	if in.NVIDIASMIOK && in.HasCUDAWorkerBin {
		return "cuda"
	}
	// Unknown named adapters — never force OpenCL just because a display name exists.
	if len(rep.Names) > 0 && in.HasOCLWorkerBin {
		return "opencl"
	}
	return "cpu"
}

// ProbeWorkerBins checks repo bin/ for workerpoh-cuda and workerpoh-opencl.
func ProbeWorkerBins(repoRoot string) (cudaBin, oclBin bool) {
	if repoRoot == "" {
		return false, false
	}
	roots := []string{repoRoot, filepath.Join(repoRoot, "bin")}
	for _, root := range roots {
		for _, name := range []string{"workerpoh-cuda", "workerpoh-cuda.exe"} {
			if st, err := os.Stat(filepath.Join(root, name)); err == nil && !st.IsDir() {
				cudaBin = true
				break
			}
		}
		for _, name := range []string{"workerpoh-opencl", "workerpoh-opencl.exe"} {
			if st, err := os.Stat(filepath.Join(root, name)); err == nil && !st.IsDir() {
				oclBin = true
				break
			}
		}
	}
	return cudaBin, oclBin
}

func envTruthy(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
