package ebpf

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"os"
)

// Custom KernelConfigOption's to extend kernel_config helper support
// Add here all kconfig variables used within tracee.bpf.c
const (
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER helpers.KernelConfigOption = iota + helpers.CUSTOM_OPTION_START
	CONFIG_FLATMEM
	CONFIG_DISCONTMEM
	CONFIG_SPARSEMEM
	CONFIG_SPARSEMEM_VMEMMAP
	CONFIG_SPARSEMEM_EXTREME
	CONFIG_DYNAMIC_MEMORY_LAYOUT
	CONFIG_X86_32
	CONFIG_X86_PAE
)

var kconfigUsed = map[helpers.KernelConfigOption]string{
	CONFIG_ARCH_HAS_SYSCALL_WRAPPER: "CONFIG_ARCH_HAS_SYSCALL_WRAPPER",
	CONFIG_FLATMEM:                  "CONFIG_FLATMEM",
	CONFIG_DISCONTMEM:               "CONFIG_DISCONTMEM",
	CONFIG_SPARSEMEM:                "CONFIG_SPARSEMEM",
	CONFIG_SPARSEMEM_VMEMMAP:        "CONFIG_SPARSEMEM_VMEMMAP",
	CONFIG_SPARSEMEM_EXTREME:        "CONFIG_SPARSEMEM_EXTREME",
	CONFIG_DYNAMIC_MEMORY_LAYOUT:    "CONFIG_DYNAMIC_MEMORY_LAYOUT",
	CONFIG_X86_32:                   "CONFIG_X86_32",
	CONFIG_X86_PAE:                  "CONFIG_X86_PAE",
}

// loadKconfigValues load all kconfig variables used within tracee.bpf.c
func loadKconfigValues(kc *helpers.KernelConfig, isDebug bool) map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue {
	values := make(map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue)
	var err error
	for key, keyString := range kconfigUsed {
		if err = kc.AddCustomKernelConfig(key, keyString); err != nil {
			return err
		}
	}

	// re-load kconfig and get just added kconfig option values
	if err = kc.LoadKernelConfig(); err != nil { // invalid kconfig file: assume values then
		if isDebug {
			fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
		}
		for key, _ := range kconfigUsed {
			values[key] = helpers.UNDEFINED
		}
		values[CONFIG_ARCH_HAS_SYSCALL_WRAPPER] = helpers.BUILTIN // assume CONFIG_ARCH_HAS_SYSCALL_WRAPPER is a BUILTIN option
	} else {
		for key, _ := range kconfigUsed {
			values[key] = kc.GetValue(key) // undefined, builtin OR module
		}
	}
	return values
}

type KernelGlobalsKey uint32

const (
	PAGE_OFFSET_BASE KernelGlobalsKey = iota
	VMEMMAP_BASE
)

type KernelConstsKey uint32

// Constants which are globally implemented
const (
	SECTIONS_WIDTH KernelConstsKey = iota
	SECTIONS_PGOFF
	SECTIONS_PGSHIFT
	SECTIONS_MASK
	SECTIONS_PER_ROOT
	SECTION_ROOT_MASK
	ARCH_PFN_OFFSET
	SECTION_MAP_LAST_BIT
	SECTION_MAP_MASK
	VMEMMAP_START
)

// Constants whichl are implemented per architecture
const (
	SECTION_SIZE_BITS KernelConstsKey = iota + 1000
	MAX_PHYSMEM_BITS
	PAGE_SHIFT
	PAGE_SIZE
	PAGE_OFFSET
)

// X86_64 specific constants
const (
	X86_FEATURE_LA57 KernelConstsKey = iota + 2000
)

const UNSIGNED_LONG_SIZE = 8

// calculateKernelConsts calculates defined values from the kernel according to version and kconfig values to be used
// by the BPF programs
func calculateKernelConsts(kconfigValues map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue,
	kernelGlobalArgs map[KernelGlobalsKey]int, osInfo *helpers.OSInfo) map[KernelConstsKey]int {
	kernelConsts := make(map[KernelConstsKey]int)
	// x86_64 values
	kernelConsts[SECTION_SIZE_BITS] = 27
	kernelConsts[X86_FEATURE_LA57] = 16*32 + 16
	kernelConsts[MAX_PHYSMEM_BITS] = 52 // TODO: Actually calculating this value according to l5 paging
	kernelConsts[PAGE_SHIFT] = 12
	kernelConsts[PAGE_SIZE] = 1 << kernelConsts[PAGE_SHIFT]
	if kconfigValues[CONFIG_DYNAMIC_MEMORY_LAYOUT] == helpers.BUILTIN {
		// check
		kernelConsts[PAGE_OFFSET] = kernelGlobalArgs[PAGE_OFFSET_BASE]
	} else {
		kernelConsts[PAGE_OFFSET] = 0xffff888000000000 // check
	}

	// General values
	if kconfigValues[CONFIG_SPARSEMEM] == helpers.BUILTIN && kconfigValues[CONFIG_SPARSEMEM_VMEMMAP] == helpers.UNDEFINED {
		sectionsShift := kernelConsts[MAX_PHYSMEM_BITS] - kernelConsts[SECTION_SIZE_BITS]
		kernelConsts[SECTIONS_WIDTH] = sectionsShift
	} else {
		kernelConsts[SECTIONS_WIDTH] = 0
	}
	kernelConsts[SECTIONS_PGOFF] = (UNSIGNED_LONG_SIZE * 8) - kernelConsts[SECTIONS_WIDTH]
	if kernelConsts[SECTIONS_WIDTH] != 0 {
		kernelConsts[SECTIONS_PGSHIFT] = kernelConsts[SECTIONS_PGOFF]
	} else {
		kernelConsts[SECTIONS_PGSHIFT] = 0
	}
	kernelConsts[SECTIONS_MASK] = (1 << kernelConsts[SECTIONS_WIDTH]) - 1
	if kconfigValues[CONFIG_SPARSEMEM_EXTREME] == helpers.BUILTIN {
		kernelConsts[SECTIONS_PER_ROOT] = kernelConsts[PAGE_SIZE] // TODO: / sizeof(struct mem_section)
	} else {
		kernelConsts[SECTIONS_PER_ROOT] = 1
	}
	kernelConsts[SECTION_ROOT_MASK] = kernelConsts[SECTIONS_PER_ROOT] - 1
	kernelConsts[ARCH_PFN_OFFSET] = kernelConsts[PAGE_OFFSET] >> kernelConsts[PAGE_SHIFT]
	if osInfo.CompareOSBaseKernelRelease("5.3") == -1 {
		kernelConsts[SECTION_MAP_LAST_BIT] = 1 << 3
	} else if osInfo.CompareOSBaseKernelRelease("5.12") == -1 {
		kernelConsts[SECTION_MAP_LAST_BIT] = 1 << 4
	} else {
		kernelConsts[SECTION_MAP_LAST_BIT] = 1 << 5
	}
	kernelConsts[SECTION_MAP_MASK] = ^(kernelConsts[SECTION_MAP_LAST_BIT] - 1)
	kernelConsts[VMEMMAP_START] = kernelGlobalArgs[VMEMMAP_BASE]

	return kernelConsts
}
