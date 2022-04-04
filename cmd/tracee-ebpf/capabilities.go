package main

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/syndtr/gocapability/capability"
)

const bpfCapabilitiesMinKernelVersion = "5.8"

// ensureCapabilities makes sure the program has just the required capabilities to run
func ensureCapabilities(OSInfo *helpers.OSInfo, cfg *tracee.Config) error {
	selfCap, err := capabilities.Self()
	if err != nil {
		return err
	}

	rCaps, err := getBPFCapabilities(selfCap, OSInfo)
	if err != nil {
		return err
	}
	rCaps = append(rCaps, buildStaticCapabilitiesSet()...)
	rCaps = append(rCaps, analyzeDynamicCapabilities(cfg)...)

	rCaps = removeDupCaps(rCaps)
	if err = capabilities.CheckRequired(selfCap, rCaps); err != nil {
		return err
	}
	if err = capabilities.DropUnrequired(selfCap, rCaps); err != nil {
		return err
	}
	return nil
}

// analyzeDynamicCapabilities process the configuration of tracee and determines which capabilities are required to
// support the functionality requested.
func analyzeDynamicCapabilities(cfg *tracee.Config) []capability.Cap {
	usedEvents := cfg.Filter.EventsToTrace
	usedEvents = append(usedEvents, tracee.CreateEssentialEventsList(cfg)...)
	caps := tracee.GetCapabilitiesRequiredByEvents(usedEvents)

	caps = append(caps, analyzeCaptureCapabilities(*cfg.Capture)...)
	return removeDupCaps(caps)
}

func analyzeCaptureCapabilities(captureCfg tracee.CaptureConfig) []capability.Cap {
	var captureCaps []capability.Cap
	if len(captureCfg.NetIfaces) > 0 {
		captureCaps = append(captureCaps, capability.CAP_NET_ADMIN)
	}
	return captureCaps
}

// getBPFCapabilities check the minimal capabilities to load eBPF programs based on given capabilities and kernel version
func getBPFCapabilities(selfCap capability.Capabilities, OSInfo *helpers.OSInfo) ([]capability.Cap, error) {
	if OSInfo.CompareOSBaseKernelRelease(bpfCapabilitiesMinKernelVersion) <= 0 {
		bpfCaps := []capability.Cap{
			capability.CAP_BPF,
			capability.CAP_PERFMON,
		}
		if err1 := capabilities.CheckRequired(selfCap, bpfCaps); err1 != nil {
			bpfCaps = []capability.Cap{
				capability.CAP_SYS_ADMIN,
			}
			if err2 := capabilities.CheckRequired(selfCap, bpfCaps); err2 != nil {
				return nil, fmt.Errorf("missing capabilites required for eBPF program loading - either CAP_BPF + CAP_PERFMON or CAP_SYS_ADMIN")
			}
		}
		return bpfCaps, nil
	} else {
		return []capability.Cap{
			capability.CAP_SYS_ADMIN,
		}, nil
	}
}

// buildStaticCapabilitiesSet creates list of minimal capabilities that are always required by tracee
func buildStaticCapabilitiesSet() []capability.Cap {
	return []capability.Cap{
		capability.CAP_IPC_LOCK,
		capability.CAP_SYS_RESOURCE,
	}
}

func removeDupCaps(dupCaps []capability.Cap) []capability.Cap {
	capsMap := make(map[capability.Cap]bool)
	for _, c := range dupCaps {
		capsMap[c] = true
	}
	caps := make([]capability.Cap, len(capsMap))
	i := 0
	for c := range capsMap {
		caps[i] = c
		i++
	}
	return caps
}
