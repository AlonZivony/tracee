package proctree

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// processExecEvent fills process information as any other general event,
// but add execution information.
func (tree *ProcessTree) processExecEvent(event *trace.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	process.Mutex.Lock()
	defer process.Mutex.Unlock()
	process.ExecutionBinary, process.Cmd, err = parseExecArguments(event)
	if err != nil {
		return err
	}
	process.ProcessName = event.ProcessName
	process.ExecTime = timestamp(event.Timestamp)

	process.Status.Add(uint32(executed))
	return nil
}

// parseExecArguments get from the exec event all relevant information for the process tree - the
// binary information of the executed binary and the argv of the execution.
func parseExecArguments(event *trace.Event) (BinaryInfo, []string, error) {
	var binaryInfo BinaryInfo
	cmd, err := helpers.GetTraceeSliceStringArgumentByName(*event, "argv")
	if err != nil {
		return binaryInfo, cmd, err
	}
	path, err := helpers.GetTraceeStringArgumentByName(*event, "pathname")
	if err != nil {
		return binaryInfo, cmd, err
	}
	ctime, err := helpers.GetTraceeUIntArgumentByName(*event, "ctime")
	if err != nil {
		return binaryInfo, cmd, err
	}
	inode, err := helpers.GetTraceeUIntArgumentByName(*event, "inode")
	if err != nil {
		return binaryInfo, cmd, err
	}
	dev, err := helpers.GetTraceeUIntArgumentByName(*event, "dev")
	if err != nil {
		return binaryInfo, cmd, err
	}

	hash, _ := helpers.GetTraceeStringArgumentByName(*event, "sha256")

	binaryInfo = BinaryInfo{
		Path:   path,
		Hash:   hash,
		Ctime:  ctime,
		Inode:  inode,
		Device: dev,
	}
	return binaryInfo, cmd, nil
}
