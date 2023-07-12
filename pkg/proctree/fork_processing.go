package proctree

import (
	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

type taskIds struct {
	Pid  int
	Tid  int
	Ppid int
}

// ProcessForkEvent add new process to process tree if new process created,
// or update process threads if new thread created.
// Because the fork at start is only a copy of the father,
// the important information regarding of the process information and binary will be collected
// upon execve.
func (tree *ProcessTree) ProcessForkEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}

	newHostIds, err := parseForkHostIds(event)
	if err != nil {
		return err
	}
	newNsIds, err := parseForNsIds(event)
	if err != nil {
		return err
	}

	if newHostIds.Pid == newHostIds.Tid {
		err = tree.addForkProcess(event, newHostIds, newNsIds)
		if err != nil {
			return err
		}
	}
	return tree.addForkThread(event, newHostIds, newNsIds)
}

// addForkProcess create a new process using fork event and the IDs given to the new process
// Notice that the new process information is a duplicate of the father, until an exec will occur.
func (tree *ProcessTree) addForkProcess(event *trace.Event, newInHostIds taskIds, newInNsIds taskIds) error {
	newProcess, err := tree.getProcess(newInHostIds.Pid)
	// If it is a new process or if for some reason the existing process is a result of lost exit
	// event
	if err != nil ||
		newProcess.getForkTime() != 0 {
		tree.immediateRemoveProcessFromTree(newInHostIds.Pid)
		newProcess, err = tree.newForkedProcessNode(newInHostIds, newInNsIds)
		if err != nil {
			return err
		}
	}
	newProcess.mutex.Lock()
	tree.copyParentBinaryInfo(types.Timestamp(event.Timestamp), newProcess)

	newProcess.setGeneralInfoProtected(
		newInNsIds.Pid,
		event.UserID,
		event.Container.ID,
	)

	newProcess.setForkTime(types.Timestamp(event.Timestamp))
	newProcess.mutex.Unlock()
	return nil
}

// addForkThread create a new thread using fork event and the IDs given to the new thread
func (tree *ProcessTree) addForkThread(event *trace.Event, newInHostIds taskIds, newInNsIds taskIds) error {
	process, err := tree.getProcess(newInHostIds.Pid)
	if err != nil {
		return err
	}
	process.mutex.Lock()
	newThread, err := tree.newProcessThreadNode(process, newInHostIds.Tid)
	if err != nil {
		process.mutex.Unlock()
		return err
	}

	processExitTime := process.getExitTime()
	process.mutex.Unlock()
	newThread.mutex.Lock()
	newThread.setForkTime(types.Timestamp(event.Timestamp))
	newThread.setName(types.Timestamp(event.Timestamp), event.ProcessName)
	newThread.setGeneralInfoProtected(
		newInNsIds.Tid,
		event.ProcessName,
		NamespacesIds{
			Pid:   event.PIDNS,
			Mount: event.MountNS,
		},
		processExitTime,
	)
	newThread.mutex.Unlock()
	return nil
}

// parseForkHostIds gets the new forked process Ids in the host PId namespace
func parseForkHostIds(event *trace.Event) (taskIds, error) {
	var inHostIds taskIds
	var err error
	inHostIds.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_pid")
	if err != nil {
		return inHostIds, err
	}
	inHostIds.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_tid")
	if err != nil {
		return inHostIds, err
	}
	inHostIds.Ppid = event.HostProcessID

	return inHostIds, nil
}

// parseForNsIds get the new forked process Ids in the process PId namespace
func parseForNsIds(event *trace.Event) (taskIds, error) {
	var inContainerIds taskIds
	var err error
	inContainerIds.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_pid")
	if err != nil {
		return inContainerIds, err
	}
	inContainerIds.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_tid")
	if err != nil {
		return inContainerIds, err
	}
	inContainerIds.Ppid = event.ProcessID

	return inContainerIds, nil
}

// newForkedProcessNode create a new process node in the process tree.
// It will connect it to its parent process if it is not the first process in the container.
func (tree *ProcessTree) newForkedProcessNode(
	inHostIds taskIds,
	inContainerIds taskIds,
) (*processNode, error) {
	newProcess, err := tree.newProcessNode(inHostIds.Pid)
	if err != nil {
		return nil, err
	}
	newProcess.mutex.Lock()
	defer newProcess.mutex.Unlock()

	if inContainerIds.Ppid != 0 &&
		inHostIds.Pid != inHostIds.Ppid { // Prevent looped references
		fatherProcess, err := tree.getProcess(inHostIds.Ppid)
		if err == nil {
			newProcess.connectParent(fatherProcess)
			fatherProcess.mutex.Lock()
			fatherProcess.connectChild(newProcess)
			fatherProcess.mutex.Unlock()
		}
	}
	return newProcess, nil
}

// copyParentBinaryInfo copies the binary information of the parent node information if exist to
// the given process node.
// This is useful for forked processes, as they have the same binary as parent process until exec
// is invoked.
func (tree *ProcessTree) copyParentBinaryInfo(time types.Timestamp, p *processNode) {
	fatherProcess := p.getParent()
	if fatherProcess == nil {
		return
	}
	fatherProcess.mutex.RLock()
	fatherExecInfo := fatherProcess.getExecInfo(time)
	fatherProcess.mutex.RUnlock()
	p.setDefaultExecInfo(fatherExecInfo)
}
