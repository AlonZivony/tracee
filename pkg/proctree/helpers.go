package proctree

import (
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/utils/types"

	"github.com/aquasecurity/tracee/types/trace"
)

// addGeneralEventProcess generate a new process with information that could be received from any event from the process
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

// generateParentProcess add a parent process to given process from tree if existing or creates new node with best
// effort info
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
				Status: *roaring.BitmapOf(uint32(hollowParent)),
			}
			tree.processes.Set(parentProcess.InHostIDs.Pid, parentProcess)
		}
		process.ParentProcess = parentProcess
		parentProcess.ChildProcesses = append(parentProcess.ChildProcesses, process)
	}
	return process
}

func fillHollowParentProcessGeneralEvent(p *processNode, event *trace.Event) {
	fillHollowProcessInfo(
		p,
		threadIDs{ProcessIDs: ProcessIDs{Pid: event.HostProcessID, Ppid: event.HostParentProcessID}, Tid: event.HostThreadID},
		ProcessIDs{Pid: event.ProcessID, Ppid: event.ParentProcessID},
		event.ProcessName,
		event.Container.ID,
	)
}

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

func (p *processNode) addThread(tid int) {
	t, exist := p.Threads.Get(tid)
	if !exist {
		p.Threads.Set(tid, &threadInfo{})
	} else {
		if t.exitTime == 0 {
			// Update thread exit time to match process if process exited
			t.exitTime = p.ExitTime
		}
	}
}
