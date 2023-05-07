package proctree

import (
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/utils/types"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

type threadIDs struct {
	ProcessIDs
	Tid int
}

// processForkEvent add new process to process tree if new process created, or update process threads if new thread
// created. Because the fork at start is only a copy of the father, the important information regarding of the
// process information and binary will be collected upon execve.
func (tree *ProcessTree) processForkEvent(event *trace.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}

	newProcessInHostIDs, err := parseForkInHostIDs(event)
	if err != nil {
		return err
	}

	if newProcessInHostIDs.Pid == newProcessInHostIDs.Tid {
		err = tree.processMainThreadFork(event, newProcessInHostIDs)
	} else {
		err = tree.processThreadFork(event, newProcessInHostIDs)
	}
	return err
}

// processMainThreadFork add new process to the tree with all possible information available.
// Notice that the new process information is a duplicate of the father, until an exec will occur.
func (tree *ProcessTree) processMainThreadFork(event *trace.Event, inHostIDs threadIDs) error {
	inContainerIDs, err := parseForkInContainerIDs(event)
	if err != nil {
		return err
	}

	newProcess, npErr := tree.getProcess(inHostIDs.Pid)
	// If it is a new process or if for some reason the existing process is a result of lost exit event
	if npErr != nil ||
		newProcess.Status.Contains(uint32(forked)) {
		newProcess = tree.addNewForkedProcess(event, inHostIDs, inContainerIDs)
	}

	// If exec did not happen yet, add binary information of parent
	if !newProcess.Status.Contains(uint32(executed)) {
		tree.copyParentBinaryInfo(newProcess)
	}
	if newProcess.Status.Contains(uint32(hollowParent)) {
		fillHollowProcessInfo(
			newProcess,
			inHostIDs,
			inContainerIDs.ProcessIDs,
			event.Container.ID,
			event.ProcessName,
		)
	}

	newProcess.addThread(inHostIDs.Tid)
	newThread, _ := newProcess.Threads.Get(inHostIDs.Tid)
	newThread.forkTime = timestamp(event.Timestamp)
	newProcess.StartTime = timestamp(event.Timestamp)
	newProcess.Status.Add(uint32(forked))
	return nil
}

// processThreadFork add new invoked thread to process threads.
func (tree *ProcessTree) processThreadFork(event *trace.Event, newInHostIDs threadIDs) error {
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return err
	}
	process.addThread(newInHostIDs.Tid)
	newThread, _ := process.Threads.Get(newInHostIDs.Tid)
	newThread.forkTime = timestamp(event.Timestamp)
	return nil
}

func parseForkInHostIDs(event *trace.Event) (threadIDs, error) {
	var inHostIDs threadIDs
	var err error
	inHostIDs.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_pid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_tid")
	if err != nil {
		return inHostIDs, err
	}
	inHostIDs.Ppid = event.HostProcessID

	return inHostIDs, nil
}

func parseForkInContainerIDs(event *trace.Event) (threadIDs, error) {
	var inContainerIDs threadIDs
	var err error
	inContainerIDs.Pid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_pid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Tid, err = helpers.GetTraceeIntArgumentByName(*event, "child_ns_tid")
	if err != nil {
		return inContainerIDs, err
	}
	inContainerIDs.Ppid = event.ProcessID

	return inContainerIDs, nil
}

func (tree *ProcessTree) addNewForkedProcess(event *trace.Event, inHostIDs threadIDs, inContainerIDs threadIDs) *processNode {
	newProcess := &processNode{
		ProcessName:    event.ProcessName,
		InHostIDs:      inHostIDs.ProcessIDs,
		InContainerIDs: inContainerIDs.ProcessIDs,
		ContainerID:    event.Container.ID,
		StartTime:      timestamp(event.Timestamp),
		IsAlive:        true,
		Status:         *roaring.BitmapOf(uint32(forked), uint32(generalCreated)),
		Threads:        types.InitRWMap[int, *threadInfo](),
	}
	if newProcess.InContainerIDs.Ppid != 0 &&
		newProcess.InHostIDs.Pid != newProcess.InHostIDs.Ppid { // Prevent looped references
		fatherProcess, err := tree.getProcess(newProcess.InHostIDs.Ppid)
		if err == nil {
			newProcess.ParentProcess = fatherProcess
			fatherProcess.ChildProcesses = append(fatherProcess.ChildProcesses, newProcess)
		}
	}
	// This will delete old instance if its exit was missing
	tree.processes.Set(inHostIDs.Pid, newProcess)
	return newProcess
}

func (tree *ProcessTree) copyParentBinaryInfo(p *processNode) {
	if p.Status.Contains(uint32(forked)) {
		fatherProcess, err := tree.getProcess(p.InHostIDs.Ppid)
		if err == nil {
			p.ExecutionBinary = fatherProcess.ExecutionBinary
			p.Cmd = fatherProcess.Cmd
		}
	}
}
