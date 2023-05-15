package proctree

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// processExitEvent remove references of processes from the tree when the corresponding process
// exit without children, or if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
// (but is limited to the possible number of PIDs - 32768).
func (tree *ProcessTree) processExitEvent(event *trace.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	thread := process.addThreadBasic(event.HostThreadID)
	thread.fillExitInfo(timestamp(event.Timestamp))

	processGroupExit, err := helpers.GetTraceeBoolArgumentByName(*event, "process_group_exit")
	if err != nil {
		return err
	}

	if processGroupExit {
		process.fillExitInfo(timestamp(event.Timestamp))
		for _, tid := range process.Threads.Keys() {
			tnode, ok := process.Threads.Get(tid)
			if ok {
				tnode.fillDefaultExitInfo(timestamp(event.Timestamp))
			}
		}
		tree.cachedDeleteProcess(process.InHostIDs.Pid)
	}
	return nil
}

const cachedDeadEvents = 100

// cachedDeleteProcess delete the process in delay.
// This is done to keep the information of the process available in the process tree for some grace
// period before making it unavailable.
// To avoid uncontrolled leaking, the delay is determined by the amount of events already queued
// to be deleted.
// We have no reason to delete the information fast, only if we encountered PID reuse.
func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		tree.deleteProcessFromTree(dpid)
	}
}

// emptyDeadProcessesCache delete all processes queued to deletion, and empty the cache list.
func (tree *ProcessTree) emptyDeadProcessesCache() {
	for _, dpid := range tree.deadProcessesCache {
		tree.deleteProcessFromTree(dpid)
	}
	tree.deadProcessesCache = []int{}
}

// deleteProcessFromTree remove the given process from the tree, and remove its connections from
// its ancestors.
// We want to keep process nodes as long as they have living children (or grandchildren,
// grand-grandchildren, etc.).
// To support this functionality,
// we don't remove process node if least one of its children nodes is alive.
// To avoid memory leak, we delete also all ancestors of the process that have no living children.
func (tree *ProcessTree) deleteProcessFromTree(dpid int) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	// Make sure that the process is not deleted because missed children
	if len(p.ChildProcesses) == 0 {
		tree.deleteNodeAndDeadAncestorsFromTree(p)
	}
}

// forceDeleteProcessFromTree remove a process from the tree regardless of if it has living
// children or its state.
// It will delete the reference to itself from the children and parent, and invoke normal deletion
// on ancestors if they are dead without living children.
func (tree *ProcessTree) forceDeleteProcessFromTree(dpid int) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	p.Mutex.RLock()
	children := p.ChildProcesses
	p.Mutex.RUnlock()
	for _, childProcess := range children {
		childProcess.Mutex.RLock()
		childParentProcess := childProcess.ParentProcess
		childProcess.Mutex.RUnlock()
		if childParentProcess == p {
			childProcess.disconnectFromParent()
		}
	}
	tree.deleteNodeAndDeadAncestorsFromTree(p)
}

// deleteNodeAndDeadAncestorsFromTree Remove process and all dead ancestors so only processes
// which are alive or with living descendants will remain.
func (tree *ProcessTree) deleteNodeAndDeadAncestorsFromTree(pn *processNode) {
	for {
		pn.Mutex.RLock()
		tree.processes.Delete(pn.InHostIDs.Pid)
		threads := pn.Threads.Values()
		parent := pn.ParentProcess
		pn.Mutex.RUnlock()

		pn.disconnectFromThreads()
		for _, thread := range threads {
			thread.disconnectFromProcess()
		}
		if parent == nil {
			return
		}
		parent.disconnectChild(pn)
		parent.Mutex.RLock()
		// If parent is still alive, or it has living children nodes, we don't want to delete it
		shouldKeepParent := parent.IsAlive || len(parent.ChildProcesses) > 0
		parent.Mutex.Unlock()
		if shouldKeepParent {
			return
		}
		pn = parent
	}
}
