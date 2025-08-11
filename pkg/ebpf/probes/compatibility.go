package probes

import (
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// ProbeCompatibility stores the requirements for a probe to be used.
// It is used to check if a probe is compatible with the current OS.
type ProbeCompatibility struct {
	probe        Handle
	requirements []ProbeRequirement
}

func NewProbeCompatibility(probe Handle, requirements []ProbeRequirement) *ProbeCompatibility {
	return &ProbeCompatibility{
		probe:        probe,
		requirements: requirements,
	}
}

// IsCompatible checks if the probe is compatible with the current OS.
func (p *ProbeCompatibility) IsCompatible(osInfo OSInfoProvider) (bool, error) {
	isAllCompatible := true
	for _, requirement := range p.requirements {
		isCompatible, err := requirement.IsCompatible(osInfo)
		if err != nil {
			return false, err
		}
		isAllCompatible = isAllCompatible && isCompatible
	}
	return isAllCompatible, nil
}

// ProbeRequirement is an interface that defines the requirements for a probe to be used.
type ProbeRequirement interface {
	IsCompatible(osInfo OSInfoProvider) (bool, error)
}

// KernelVersionRequirement is a requirement that checks if the kernel version and distro are compatible.
type KernelVersionRequirement struct {
	distro           string
	minKernelVersion string
	maxKernelVersion string
}

// NewKernelVersionRequirement creates a new KernelVersionRequirement.
func NewKernelVersionRequirement(distro, minKernelVersion, maxKernelVersion string) *KernelVersionRequirement {
	return &KernelVersionRequirement{
		distro:           distro,
		minKernelVersion: minKernelVersion,
		maxKernelVersion: maxKernelVersion,
	}
}

// IsCompatible checks if the kernel version and distro are compatible.
func (k *KernelVersionRequirement) IsCompatible(osInfo OSInfoProvider) (bool, error) {
	// If distro is specified, check if it matches
	// Only if the distro is matching then the kernel version is relevant.
	// Empty distro means that the kernel version is relevant for all distros.
	if k.distro != "" && osInfo.GetOSReleaseID().String() != strings.ToLower(k.distro) {
		return true, nil
	}

	// If minKernelVersion is specified, check if osInfo.KernelVersion >= minKernelVersion
	if k.minKernelVersion != "" {
		comparison, err := osInfo.CompareOSBaseKernelRelease(k.minKernelVersion)
		if err != nil {
			return false, err
		}
		// If provided kernel version is newer, the probe is under the minimum version, so it is not compatible.
		if comparison == environment.KernelVersionNewer {
			return false, nil
		}
	}

	// If maxKernelVersion is specified, check if osInfo.KernelVersion <= maxKernelVersion
	if k.maxKernelVersion != "" {
		comparison, err := osInfo.CompareOSBaseKernelRelease(k.maxKernelVersion)
		if err != nil {
			return false, err
		}
		// If provided kernel version is older, the probe is over the maximum version, so it is not compatible.
		if comparison == environment.KernelVersionOlder {
			return false, nil
		}
	}

	return true, nil
}

// BPFHelperRequirement is a requirement that checks if a specific BPF helper function is supported.
type BPFHelperRequirement struct {
	progType bpf.BPFProgType
	funcID   bpf.BPFFunc
}

// NewBPFHelperRequirement creates a new BPFHelperRequirement.
func NewBPFHelperRequirement(progType bpf.BPFProgType, funcID bpf.BPFFunc) *BPFHelperRequirement {
	return &BPFHelperRequirement{
		progType: progType,
		funcID:   funcID,
	}
}

// IsCompatible checks if the BPF helper function is supported.
func (b *BPFHelperRequirement) IsCompatible(osInfo OSInfoProvider) (bool, error) {
	supported := false

	err := capabilities.GetInstance().EBPF(
		func() error {
			var err error
			// Since this code is running with sufficient capabilities, we can safely trust the result of `BPFHelperIsSupported`.
			// If the helper is reported as supported (`supported == true`), it is assumed to be reliable for use.
			// If `supported == false`, it indicates that the helper is not available.
			// The `innerErr` provides information about errors that occurred during the check, regardless of whether `supported`
			// is true or false.
			// For a full explanation of the caveats and behavior, refer to:
			// https://github.com/aquasecurity/libbpfgo/blob/eb576c71ece75930a693b8b0687c5d052a5dbd56/libbpfgo.go#L99-L119
			supported, err = bpf.BPFHelperIsSupported(b.progType, b.funcID)

			if err != nil {
				return err
			}

			return nil
		})
	return supported, err
}
