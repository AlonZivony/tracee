package proctree

/*
Package proctree is used to create and maintain a process tree using Tracee's events.

The process tree exports to the user only read operations - the user can query for a processes and
threads information.
However, the process tree itself is rather complicated, and shouldn't be changed by unsupported
methods.
Currently, the only supported way to update and change the process tree is via events. The process
tree is aware of Tracee's events, and know how to update itself using events. It can be done
using a pipeline or directly using the appropriate method.

# Synchronization

The tree usage is not synchronized.
Process information might be requested some time after it was updated, or even deleted.
To address this issue, the tree:
*	Makes processes available even after they are exited and should be deleted for some time.
*	Exports processes and threads information according to a specific time, instead of giving the
	entire information and leaving the user to process it.

# Events feeding edge cases handling

The overall design of the tree is taking into consideration that events are not guaranteed to be
ordered, nor they are guaranteed to arrive at all.
Moreover, the tree needs to take into account that it starts running in the middle of the system
runtime. As a result, it missed some processes fork, exec and exit events.
To withstand this issues, the tree do the following things:
*	Limit the amount of nodes it keeps, to avoid leakage when missing exit events.
*	Take information from all events, even those which are not related to process and thread life
	cycle.
*	Try cleaning processes with PID which is found to be reused by new fork events.
*	Initializing parent processes nodes, even with almost no information, to establish connections
	between known nodes.
*	The tree is *not* trying to create one big tree, but instead has the forest architecture.
	As it doesn't have all the history, it can't connect all nodes, and so it connects only nodes
	it knows are connected.
*/

import (
	gocontext "context"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// GetProcessInfo return the process information from the process tree relevant to the given time
func (tree *ProcessTree) GetProcessInfo(hostProcessID int, time int) (ProcessInfo, error) {
	pn, err := tree.getProcess(hostProcessID)
	if err != nil {
		return ProcessInfo{}, err
	}
	return pn.export(types.Timestamp(time)), nil
}

// GetThreadInfo return the thread information from the process tree relevant to the given time
func (tree *ProcessTree) GetThreadInfo(hostThreadId int, time int) (ThreadInfo, error) {
	tn, err := tree.getThread(hostThreadId)
	if err != nil {
		return ThreadInfo{}, err
	}
	return tn.export(types.Timestamp(time)), nil
}

// GetProcessLineage return list of processes, starting with given PID process and moving upward,
// of the ancestors of the process.
// This is done up to the given max depth, or either last known ancestor or the container root.
// The information of the process with given PID is relevant to the given time, and the ancestors
// information are each relevant to their lineage child fork time. This should help to provide
// information regarding the lineage which is relevant to given process.
func (tree *ProcessTree) GetProcessLineage(hostProcessID int, time int, maxDepth int) (ProcessLineage, error) {
	pList, err := tree.getProcessLineage(hostProcessID, maxDepth)
	if err != nil {
		return nil, err
	}
	lineage := make(ProcessLineage, len(pList))
	relevantTime := time
	for i, p := range pList {
		lineage[i] = p.export(types.Timestamp(relevantTime))
		relevantTime = lineage[i].StartTime
	}
	return lineage, nil
}

// StartProcessingPipeline create a goroutine that feeds the process tree from the incoming events.
func (tree *ProcessTree) StartProcessingPipeline(
	ctx gocontext.Context,
	in <-chan *trace.Event,
) (chan *trace.Event, chan error) {
	out := make(chan *trace.Event, 1000)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for {
			select {
			case e := <-in:
				err := tree.ProcessEvent(e)
				if err != nil {
					logger.Errorw("error processing event in process tree: %v", err)
				}
				out <- e
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// getProcessLineage returns list of processes starting with the PID matching process back to the
// root of the container or oldest registered ancestor in the container (if root is missing).
// You can cap the amount of ancestors given this way with the maxDepth argument.
func (tree *ProcessTree) getProcessLineage(hostProcessID int, maxDepth int) ([]*processNode, error) {
	process, err := tree.getProcess(hostProcessID)
	if err != nil {
		return nil, err
	}
	var lineage []*processNode
	depth := 0
	for process != nil && depth <= maxDepth {
		lineage = append(lineage, process)
		process.mutex.RLock()
		parent := process.getParent()
		process.mutex.RUnlock()
		process = parent
		depth++
	}
	return lineage, nil
}

// export return the process information true to the given time
func (p *processNode) export(time types.Timestamp) ProcessInfo {
	var childrenIds []int
	var threadIds []int
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	for _, child := range p.getChildren() {
		child.mutex.RLock()
		if child.isAlive(time) {
			childrenIds = append(childrenIds, child.getId())
		}
		child.mutex.RUnlock()
	}
	for _, tnode := range p.getThreads() {
		tnode.mutex.RLock()
		if tnode.isAlive(time) {
			threadIds = append(threadIds, tnode.getId())
		}
		tnode.mutex.RUnlock()
	}
	parentId := 0
	parentNsId := 0
	parent := p.getParent()
	if parent != nil {
		parent.mutex.RLock()
		parentId = parent.getId()
		parentNsId = parent.getNsId()
		parent.mutex.RUnlock()
	}

	execInfo := p.getExecInfo(time)

	return ProcessInfo{
		Id:              p.getId(),
		NsId:            p.getNsId(),
		Ppid:            parentId,
		NsPpid:          parentNsId,
		UserId:          p.getUserId(),
		ContainerId:     p.getContainerId(),
		Cmd:             execInfo.Cmd,
		ExecutionBinary: execInfo.ExecutionBinary,
		StartTime:       int(p.getForkTime()),
		ExecTime:        int(p.getExecTime(time)),
		ExitTime:        int(p.getExitTime()),
		ExistingThreads: threadIds,
		ChildrenIds:     childrenIds,
		IsAlive:         p.isAlive(time),
	}
}

func (t *threadNode) export(time types.Timestamp) ThreadInfo {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	process := t.getProcess()

	return ThreadInfo{
		HostId:        t.getId(),
		NsId:          t.getNsId(),
		HostProcessID: process.getId(),
		ForkTime:      int(t.getForkTime()),
		ExitTime:      int(t.getExitTime()),
		Namespaces:    t.getNamespaces(),
		Name:          t.getName(time),
		IsAlive:       t.isAlive(time),
	}
}
