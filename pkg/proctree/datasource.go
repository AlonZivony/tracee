package proctree

import (
	"encoding/json"

	"github.com/aquasecurity/tracee/types/detect"
)

type ProcKey struct {
	Pid  int
	Time int
}

type ThreadKey struct {
	Tid  int
	Time int
}

type LineageKey struct {
	Pid      int
	Time     int
	MaxDepth int
}

type DataSource struct {
	procTree *ProcessTree
}

func NewDataSource(processTree *ProcessTree) *DataSource {
	return &DataSource{procTree: processTree}
}

func (ptds *DataSource) Get(key interface{}) (map[string]interface{}, error) {
	switch typedKey := key.(type) {
	case ProcKey:
		procInfo, err := ptds.procTree.GetProcessInfo(typedKey.Pid, typedKey.Time)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_info": procInfo,
		}, nil
	case ThreadKey:
		threadInfo, err := ptds.procTree.GetThreadInfo(typedKey.Tid, typedKey.Time)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"thread_info": threadInfo,
		}, nil
	case LineageKey:
		procLineage, err := ptds.procTree.GetProcessLineage(typedKey.Pid, typedKey.Time, typedKey.MaxDepth)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_lineage": procLineage,
		}, nil
	default:
		return nil, detect.ErrKeyNotSupported
	}
}

func (ptds *DataSource) Keys() []string {
	return []string{"ProcKey", "ThreadKey", "LineageKey"}
}

func (ptds *DataSource) Schema() string {
	schemaMap := map[string]string{
		"process_info":    "ProcessInfo",
		"thread_info":     "ThreadInfo",
		"process_lineage": "ProcessLineage",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ptds *DataSource) Version() uint {
	return 1
}

func (ptds *DataSource) Namespace() string {
	return "tracee"
}

func (ptds *DataSource) ID() string {
	return "process_tree"
}
