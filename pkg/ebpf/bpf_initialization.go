package ebpf

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/kernelsyms"
	"os"
)

type KernelGlobalsKey uint32

const (
	PAGE_OFFSET_BASE KernelGlobalsKey = iota
	MEM_MAP
	MEM_SECTION
	VMEMMAP_BASE
	SECTION_TO_NODE_TABLE
	NODE_DATA
	SPARSE_INDEX_ALLOC_FUNC
)

var kallsymsIDToName = map[KernelGlobalsKey]string{
	PAGE_OFFSET_BASE:        "page_offset_base",
	MEM_MAP:                 "mem_map",
	MEM_SECTION:             "mem_section",
	VMEMMAP_BASE:            "vmemmap_base",
	SECTION_TO_NODE_TABLE:   "section_to_node_table",
	NODE_DATA:               "node_data",
	SPARSE_INDEX_ALLOC_FUNC: "sparse_index_alloc",
}

func loadKallsymsValues(ksyms kernelsyms.KernelSymbolTable) map[KernelGlobalsKey]kernelsyms.KernelSymbol {
	kallsymsMap := make(map[KernelGlobalsKey]kernelsyms.KernelSymbol)
	for id, name := range kallsymsIDToName {
		kallsymsMap[id], _ = ksyms.GetSymbolByName("system", name)
	}
	return kallsymsMap
}

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
func loadKconfigValues(kc *helpers.KernelConfig, symbols map[KernelGlobalsKey]kernelsyms.KernelSymbol, isDebug bool) (map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue, error) {
	values := make(map[helpers.KernelConfigOption]helpers.KernelConfigOptionValue)
	var err error
	for key, keyString := range kconfigUsed {
		if err = kc.AddCustomKernelConfig(key, keyString); err != nil {
			return nil, err
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
		if symbols[MEM_SECTION].Address != 0 {
			values[CONFIG_SPARSEMEM] = helpers.BUILTIN
			if symbols[VMEMMAP_BASE].Address != 0 {
				values[CONFIG_SPARSEMEM_VMEMMAP] = helpers.BUILTIN
			}
			if symbols[SPARSE_INDEX_ALLOC_FUNC].Address != 0 {
				values[CONFIG_SPARSEMEM_EXTREME] = helpers.BUILTIN
			}
		} else if symbols[NODE_DATA].Address != 0 {
			values[CONFIG_DISCONTMEM] = helpers.BUILTIN
		} else {
			values[CONFIG_FLATMEM] = helpers.BUILTIN
		}
		if symbols[PAGE_OFFSET_BASE].Address != 0 {
			values[CONFIG_DYNAMIC_MEMORY_LAYOUT] = helpers.BUILTIN
		}
	} else {
		for key, _ := range kconfigUsed {
			values[key] = kc.GetValue(key) // undefined, builtin OR module
		}
	}
	return values, err
}
