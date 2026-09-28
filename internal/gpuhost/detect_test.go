package gpuhost

import "testing"

func TestClassifyNameNVIDIA(t *testing.T) {
	nv, amd, intel := classifyName("NVIDIA GeForce RTX 5060 Ti")
	if !nv || amd || intel {
		t.Fatalf("nv=%v amd=%v intel=%v", nv, amd, intel)
	}
}

func TestClassifyNameAMD(t *testing.T) {
	nv, amd, intel := classifyName("AMD Radeon RX 580 2048SP")
	if nv || !amd || intel {
		t.Fatalf("nv=%v amd=%v intel=%v", nv, amd, intel)
	}
}

func TestClassifyNameIntelArc(t *testing.T) {
	nv, amd, intel := classifyName("Intel Arc A770 Graphics")
	if nv || amd || !intel {
		t.Fatalf("nv=%v amd=%v intel=%v", nv, amd, intel)
	}
}

func TestResolveBackendNVIDIAWithCUDA(t *testing.T) {
	b := ResolveBackend(BackendChoiceInput{
		Report:           HostGPUReport{HasNVIDIA: true, Names: []string{"RTX 5060 Ti"}},
		HasCUDAWorkerBin: true,
		HasOCLWorkerBin:  true,
		NVIDIASMIOK:      true,
	})
	if b != "cuda" {
		t.Fatalf("got %q want cuda", b)
	}
}

func TestResolveBackendAMDOpenCL(t *testing.T) {
	b := ResolveBackend(BackendChoiceInput{
		Report:          HostGPUReport{HasAMD: true},
		HasOCLWorkerBin: true,
	})
	if b != "opencl" {
		t.Fatalf("got %q want opencl", b)
	}
}

func TestResolveBackendNoGPU(t *testing.T) {
	b := ResolveBackend(BackendChoiceInput{Report: HostGPUReport{}})
	if b != "cpu" {
		t.Fatalf("got %q want cpu", b)
	}
}

func TestResolveBackendVirtualOnlyDisplayIsCPU(t *testing.T) {
	// VirtualBox / Hyper-V names must not force OpenCL when no real vendor GPU.
	b := ResolveBackend(BackendChoiceInput{
		Report:          HostGPUReport{Names: []string{"VirtualBox Graphics Adapter (WDDM)"}},
		HasOCLWorkerBin: true,
	})
	if b != "cpu" {
		t.Fatalf("got %q want cpu for virtual adapter", b)
	}
}

func TestIsVirtualDisplayAdapter(t *testing.T) {
	if !isVirtualDisplayAdapter("VirtualBox Graphics Adapter (WDDM)") {
		t.Fatal("expected VirtualBox adapter to be virtual")
	}
	if isVirtualDisplayAdapter("AMD Radeon RX 580") {
		t.Fatal("RX 580 must not be virtual")
	}
}

func TestResolveBackendAMDWithoutOCLBinIsCPU(t *testing.T) {
	b := ResolveBackend(BackendChoiceInput{
		Report:          HostGPUReport{HasAMD: true, Names: []string{"Radeon RX 580"}},
		HasOCLWorkerBin: false,
	})
	if b != "cpu" {
		t.Fatalf("got %q want cpu when opencl worker binary missing", b)
	}
}
