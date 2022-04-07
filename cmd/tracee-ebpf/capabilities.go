package main

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/syndtr/gocapability/capability"
)

const bpfCapabilitiesMinKernelVersion = "5.8"

// ensureCapabilities makes sure program runs with required capabilities only
func ensureCapabilities(OSInfo *helpers.OSInfo, cfg *tracee.Config) error {
	selfCap, err := capabilities.Self()
	if err != nil {
		return err
	}

	rCaps, err := getCapabilitiesRequiredByEBPF(selfCap, OSInfo)
	if err != nil {
		return err
	}
	rCaps = append(rCaps, getCapabilitiesRequiredByTracee()...)
	rCaps = append(rCaps, getCapabilitiesRequiredByTraceeConfig(cfg)...)
	rCaps = append(rCaps, getCapabilitiesRequiredByTraceeEvents(cfg)...)

	rCaps = removeDupCaps(rCaps)

	if err = capabilities.CheckRequired(selfCap, rCaps); err != nil {
		return err
	}
	if err = capabilities.DropUnrequired(selfCap, rCaps); err != nil {
		return err
	}

	return nil
}

func getCapabilitiesRequiredByTracee() []capability.Cap {
	return []capability.Cap{
		capability.CAP_IPC_LOCK,
		capability.CAP_SYS_RESOURCE,
	}
}

func getCapabilitiesRequiredByTraceeConfig(cfg *tracee.Config) []capability.Cap {
	caps := make([]capability.Cap, 0)

	if len(cfg.Capture.NetIfaces) > 0 {
		caps = append(caps, capability.CAP_NET_ADMIN)
	}

	return caps
}

func getCapabilitiesRequiredByTraceeEvents(cfg *tracee.Config) []capability.Cap {
	usedEvents := cfg.Filter.EventsToTrace
	usedEvents = append(usedEvents, tracee.CreateEssentialEventsList(cfg)...)

	caps := tracee.GetCapabilitiesRequiredByEvents(usedEvents)

	return removeDupCaps(caps)
}

func getCapabilitiesRequiredByEBPF(selfCap capability.Capabilities, OSInfo *helpers.OSInfo) ([]capability.Cap, error) {
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
