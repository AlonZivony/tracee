package proctree

import (
	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// fillGeneralInfoForHollowByEvent fill a hollow parent process node with information from a
// general event invoked by the hollowParent status process.
// Hollow parent is a node of a process created upon receiving event with unregistered parent
// process.To follow processes relations,
// we create a node for the parent to connect it to received event, but with a very basic info.
// This function purpose is to fill missing information about the hollow process after receiving an
// event from it.
func (p *processNode) fillGeneralInfoForHollowByEvent(event *trace.Event) {
	p.fillGeneralInfoForHollow(
		threadIDs{
			ProcessIDs: ProcessIDs{Pid: event.HostProcessID, Ppid: event.HostParentProcessID},
			Tid:        event.HostThreadID,
		},
		ProcessIDs{Pid: event.ProcessID, Ppid: event.ParentProcessID},
		event.ProcessName,
		event.Container.ID,
	)
}

// fillGeneralInfoForHollow is an util function to fill missing general information in process node
// with the status of hollowParent.
func (p *processNode) fillGeneralInfoForHollow(
	inHostIDs threadIDs,
	inContainerIDs ProcessIDs,
	processName string,
	containerID string,
) {
	p.Mutex.Lock()
	p.InHostIDs = inHostIDs.ProcessIDs
	p.InContainerIDs = inContainerIDs
	p.ContainerID = containerID
	p.ProcessName = processName
	p.Threads = types.InitRWMap[int, *threadNode]()
	p.IsAlive = true
	p.Status.Add(uint32(generalCreated))
	p.Mutex.Unlock()
}

func (p *processNode) fillExitInfo(exitTime timestamp) {
	p.Mutex.Lock()
	p.IsAlive = false
	p.ExitTime = exitTime
	p.Mutex.Unlock()
}

func (p *processNode) disconnectFromParent() {
	p.Mutex.Lock()
	p.ParentProcess = nil
	p.Mutex.Unlock()
}

func (p *processNode) disconnectFromThreads() {
	p.Mutex.Lock()
	p.Threads.Clear()
	p.Mutex.Unlock()
}

func (p *processNode) disconnectChild(childToDisconnect *processNode) bool {
	p.Mutex.RUnlock()
	children := p.ChildProcesses
	p.Mutex.RUnlock()
	for i, child := range children {
		if child == childToDisconnect {
			p.Mutex.Lock()
			p.ChildProcesses = append(
				p.ChildProcesses[:i],
				p.ChildProcesses[i+1:]...,
			)
			p.Mutex.Unlock()
			return true
		}
	}
	return false
}

func (p *processNode) connectParent(parent *processNode) {
	p.Mutex.Lock()
	p.ParentProcess = parent
	p.Mutex.Unlock()
}

func (p *processNode) connectChild(child *processNode) {
	p.Mutex.Lock()
	p.ChildProcesses = append(p.ChildProcesses, child)
	p.Mutex.Unlock()
}

// addThreadBasic add the thread to the process node if it does not exist.
// The function also tries to synchronize the thread exit time with the process if filled after
// process exit.
func (p *processNode) addThreadBasic(tid int) *threadNode {
	t, exist := p.Threads.Get(tid)
	if exist {
		return t
	}
	t = &threadNode{}
	// Update thread exit time to match process if process exited
	t.exitTime = p.ExitTime
	t.Process = p
	p.Threads.Set(tid, t)
	return t
}
