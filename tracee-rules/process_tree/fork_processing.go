package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

// processForkEvent add new process to the tree with all possible information available.
// Notice that the new process ID and TID are not available, and will be collected only upon exec.
func (tree *ProcessTree) processForkEvent(event external.Event) error {
	newProcessInHostIDs, err := parseForkInHostIDs(event)
	if err != nil {
		return err
	}
	newProcessInContainerIDs, err := parseForkInContainerIDs(event)
	if err != nil {
		return err
	}

	if newProcessInHostIDs.Pid == newProcessInHostIDs.Tid {
		return tree.processMainThreadFork(event, newProcessInHostIDs, newProcessInContainerIDs)
	} else {
		return tree.processThreadFork(event, newProcessInHostIDs, newProcessInContainerIDs)
	}
}

func (tree *ProcessTree) processMainThreadFork(event external.Event, inHostIDs types.ProcessIDs, inContainerIDs types.ProcessIDs) error {
	newProcess, npErr := tree.GetProcessInfo(inHostIDs.Pid)
	// If it is a new process or if for some reason the existing process is a result of lost exit event
	if npErr != nil ||
		newProcess.Status == types.Completed ||
		newProcess.Status == types.Forked {
		newProcess = tree.addNewForkedProcess(event, inHostIDs, inContainerIDs)
	}

	// If exec did not happened yet, add binary information of parent
	if newProcess.Status == types.Forked {
		tree.copyParentBinaryInfo(newProcess)
	}
	if newProcess.Status == types.HollowParent {
		fillHollowProcessInfo(
			newProcess,
			inHostIDs,
			inContainerIDs,
			event.ContainerID,
			event.ProcessName,
		)
	}

	newProcess.StartTime = event.Timestamp
	if newProcess.Status == types.Executed {
		newProcess.Status = types.Completed
	} else {
		newProcess.Status = types.Forked
	}
	return nil
}

func (tree *ProcessTree) processThreadFork(event external.Event, inHostIDs types.ProcessIDs, inContainerIDs types.ProcessIDs) error {
	newProcess, npErr := tree.GetProcessInfo(inHostIDs.Pid)
	if npErr != nil {
		// In this case, calling thread is another thread of the process and we have normal general information on it
		newProcess = tree.addGeneralEventProcess(event)
		tree.generateParentProcess(newProcess)
	} else {
		newProcess.ThreadsCount += 1
	}

	if newProcess.Status == types.HollowParent {
		fillHollowProcessInfo(
			newProcess,
			inHostIDs,
			inContainerIDs,
			event.ContainerID,
			event.ProcessName,
		)
	}
	return nil
}

func parseForkInHostIDs(event external.Event) (types.ProcessIDs, error) {
	var inHostIDs types.ProcessIDs
	var err error
	inHostIDs.Pid, err = parseInt32Field(event, "child_pid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Tid, err = parseInt32Field(event, "child_tid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Ppid = event.HostProcessID

	return inHostIDs, nil
}

func parseForkInContainerIDs(event external.Event) (types.ProcessIDs, error) {
	var inContainerIDs types.ProcessIDs
	var err error
	inContainerIDs.Pid, err = parseInt32Field(event, "child_ns_pid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Tid, err = parseInt32Field(event, "child_ns_tid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Ppid = event.ProcessID

	return inContainerIDs, nil
}

func (tree *ProcessTree) addNewForkedProcess(event external.Event, inHostIDs types.ProcessIDs, inContainerIDs types.ProcessIDs) *types.ProcessInfo {
	newProcess := &types.ProcessInfo{
		ProcessName:    event.ProcessName,
		InHostIDs:      inHostIDs,
		InContainerIDs: inContainerIDs,
		ContainerID:    event.ContainerID,
		StartTime:      event.Timestamp,
		IsAlive:        true,
		Status:         types.Forked,
		ThreadsCount:   1,
	}
	containerTree, err := tree.getContainerTree(event.ContainerID)
	if err != nil {
		containerTree = &containerProcessTree{
			Root: newProcess,
		}
		tree.containers[event.ContainerID] = containerTree
	}
	if newProcess.InContainerIDs.Ppid != 0 {
		fatherProcess, err := tree.GetProcessInfo(newProcess.InHostIDs.Ppid)
		if err == nil {
			newProcess.ParentProcess = fatherProcess
			fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, newProcess)
		}
	} else {
		containerTree.Root = newProcess
	}
	// This will delete old instance if its exit was missing
	tree.processes[inHostIDs.Pid] = newProcess
	return newProcess
}

func (tree *ProcessTree) copyParentBinaryInfo(p *types.ProcessInfo) {
	if p.Status == types.Forked {
		fatherProcess, err := tree.GetProcessInfo(p.InHostIDs.Ppid)
		if err == nil {
			p.ExecutionBinary = fatherProcess.ExecutionBinary
			p.Cmd = fatherProcess.Cmd
		}
	}
}
