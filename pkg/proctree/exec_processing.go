package proctree

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessExecEvent fills process information as any other general event,
// but add execution information.
func (tree *ProcessTree) ProcessExecEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	execInfo, err := parseExecArguments(event)
	process.mutex.Lock()
	if err != nil {
		process.mutex.Unlock()
		return err
	}
	process.setExecInfo(types.Timestamp(event.Timestamp), execInfo)
	tnode, _ := process.getThread(event.HostThreadID)
	process.mutex.Unlock()
	tnode.mutex.Lock()
	tnode.setName(types.Timestamp(event.Timestamp), event.ProcessName)
	tnode.mutex.Unlock()

	return nil
}

// parseExecArguments get from the exec event all relevant information for the process tree - the
// binary information of the executed binary and the argv of the execution.
func parseExecArguments(event *trace.Event) (procExecInfo, error) {
	var execInfo procExecInfo
	cmd, err := helpers.GetTraceeSliceStringArgumentByName(*event, "argv")
	if err != nil {
		return execInfo, err
	}
	path, err := helpers.GetTraceeStringArgumentByName(*event, "pathname")
	if err != nil {
		return execInfo, err
	}
	ctime, err := helpers.GetTraceeUIntArgumentByName(*event, "ctime")
	if err != nil {
		return execInfo, err
	}
	inode, err := helpers.GetTraceeUIntArgumentByName(*event, "inode")
	if err != nil {
		return execInfo, err
	}
	dev, err := helpers.GetTraceeUIntArgumentByName(*event, "dev")
	if err != nil {
		return execInfo, err
	}

	hash, _ := helpers.GetTraceeStringArgumentByName(*event, "sha256")

	limitStringList(cmd)
	execInfo = procExecInfo{
		ExecutionBinary: FileInfo{
			Path:   path,
			Hash:   hash,
			Ctime:  ctime,
			Inode:  inode,
			Device: dev,
		},
		Cmd: cmd,
	}
	return execInfo, nil
}

var maxStringLen = 40

func limitStringList(list []string) {
	for i, str := range list {
		if len(str) > maxStringLen {
			list[i] = str[:maxStringLen+1]
		}
	}
}
