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
		Threads:     types.InitRWMap[int, *threadNode](),
		IsAlive:     true,
		Status:      *roaring.BitmapOf(uint32(generalCreated)),
	}
	tree.processes.Set(event.HostProcessID, process)
	return process
}

// addGeneralEventThread generate a new thread with information that could be received from any
// event from the thread
func (p *processNode) addGeneralEventThread(event *trace.Event) *threadNode {
	thread := p.addThreadBasic(event.HostThreadID)

	p.Mutex.RLock()
	exitTime := p.ExitTime
	p.Mutex.RUnlock()

	thread.Mutex.Lock()
	if !thread.Status.Contains(uint32(generalCreated)) {
		ns := NamespacesIDs{
			Pid:   event.PIDNS,
			Mount: event.MountNS,
		}
		thread.fillGeneralInfo(ns, exitTime)
	}
	thread.Mutex.Unlock()
	return thread
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
				Threads: types.InitRWMap[int, *threadNode](),
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
