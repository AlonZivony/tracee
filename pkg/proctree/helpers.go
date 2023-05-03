package proctree

import (
	"github.com/RoaringBitmap/roaring"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// addGeneralEventProcess generate a new process with information that could be received from any
// event from the process
func (tree *ProcessTree) addGeneralEventProcess(event *trace.Event) *processNode {
	process := &processNode{
		ProcessName: event.ProcessName,
		InHostIDs: ProcessIDs{
			Pid:  event.HostProcessID,
			Ppid: event.HostParentProcessID,
		},
		InContainerIDs: ProcessIDs{
			Pid:  event.ProcessID,
			Ppid: event.ParentProcessID,
		},
		UserID: event.UserID,
		Namespaces: NamespacesIDs{
			Pid:   event.PIDNS,
			Mount: event.MountNS,
		},
		ContainerID: event.Container.ID,
		Threads:     types.InitRWMap[int, *threadInfo](),
		IsAlive:     true,
		Status:      *roaring.BitmapOf(uint32(generalCreated)),
	}
	tree.processes.Set(event.HostProcessID, process)
	return process
}

// generateParentProcess add a parent process to given process from tree if existing or creates
// new node with the best effort info
func (tree *ProcessTree) generateParentProcess(process *processNode) *processNode {
	if process.InContainerIDs.Ppid != 0 &&
		process.InHostIDs.Pid != process.InHostIDs.Ppid { // Prevent looped references
		parentProcess, err := tree.getProcess(process.InHostIDs.Ppid)
		if err != nil {
			parentProcess = &processNode{
				InHostIDs: ProcessIDs{
					Pid: process.InHostIDs.Ppid,
				},
				InContainerIDs: ProcessIDs{
					Pid: process.InContainerIDs.Ppid,
				},
				Status:  *roaring.BitmapOf(uint32(hollowParent)),
				Threads: types.InitRWMap[int, *threadInfo](),
			}
			tree.processes.Set(parentProcess.InHostIDs.Pid, parentProcess)
		}
		process.ParentProcess = parentProcess
		parentProcess.Mutex.Lock()
		parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, process)
		parentProcess.Mutex.Unlock()
	}
	return process
}

// fillHollowParentProcessGeneralEvent fill a hollow parent process node with information from a
// general event invoked by the hollowParent status process.
// Hollow parent is a node of a process created upon receiving event with unregistered parent
// process.To follow processes relations,
// we create a node for the parent to connect it to received event, but with a very basic info.
// This function purpose is to fill missing information about the hollow process after receiving an
// event from it.
func fillHollowParentProcessGeneralEvent(p *processNode, event *trace.Event) {
	fillHollowProcessInfo(
		p,
		threadIDs{
			ProcessIDs: ProcessIDs{Pid: event.HostProcessID, Ppid: event.HostParentProcessID},
			Tid:        event.HostThreadID,
		},
		ProcessIDs{Pid: event.ProcessID, Ppid: event.ParentProcessID},
		event.ProcessName,
		event.Container.ID,
	)
}

// fillHollowProcessInfo is an util function to fill missing general information in process node
// with the status of hollowParent.
func fillHollowProcessInfo(
	p *processNode,
	inHostIDs threadIDs,
	inContainerIDs ProcessIDs,
	processName string,
	containerID string,
) {
	p.InHostIDs = inHostIDs.ProcessIDs
	p.InContainerIDs = inContainerIDs
	p.ContainerID = containerID
	p.ProcessName = processName
	p.Threads = types.InitRWMap[int, *threadInfo]()
	p.IsAlive = true
	p.Status.Add(uint32(generalCreated))
	p.Status.Remove(uint32(hollowParent))
}

// addThread add the thread to the process node if it does not exist.
// The function also tries to synchronize the thread exit time with the process if filled after
// process exit.
func (p *processNode) addThread(tid int) {
	t, exist := p.Threads.Get(tid)
	if !exist {
		t = &threadInfo{}
		p.Threads.Set(tid, t)
	}
	if t.exitTime == 0 {
		// Update thread exit time to match process if process exited
		t.exitTime = p.ExitTime
	}
}
