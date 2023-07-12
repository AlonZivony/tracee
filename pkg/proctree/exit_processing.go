package proctree

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessExitEvent remove references of processes from the tree when the corresponding process
// exit without children, or if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
// (but is limited to the possible number of PIds - 32768).
func (tree *ProcessTree) ProcessExitEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	thread, err := tree.newProcessThreadNode(process, event.HostThreadID)
	if err != nil {
		return nil
	}
	thread.mutex.Lock()
	thread.setExitTime(types.Timestamp(event.Timestamp))
	thread.mutex.Unlock()

	processGroupExit, err := helpers.GetTraceeBoolArgumentByName(*event, "process_group_exit")
	if err != nil {
		return err
	}

	if processGroupExit {
		process.setExitTime(types.Timestamp(event.Timestamp))
		for _, tnode := range process.getThreads() {
			tnode.setDefaultExitTime(types.Timestamp(event.Timestamp))
		}
		tree.cachedRemoveProcess(process.getId())
	}
	return nil
}

// cachedRemoveProcess remove the process from the tree in delay.
// This is done to keep the information of the process available in the process tree for some grace
// period before making it unavailable.
// To avoid uncontrolled leaking, the delay is determined by the amount of events already queued
// to be deleted.
// We have no reason to delete the information fast, only if we encountered PID reuse.
func (tree *ProcessTree) cachedRemoveProcess(pid int) {
	tree.deadProcessesCache.Add(pid, true)
}

// emptyDeadProcessesCache delete all processes queued to deletion, and empty the cache list.
func (tree *ProcessTree) emptyDeadProcessesCache() {
	tree.deadProcessesCache.Purge()
}

// removeProcessFromTree remove the given process from the tree, and remove its connections from
// its ancestors.
// However, we want to keep process nodes as long as they have living children (or grandchildren,
// grand-grandchildren, etc.).
// To support this functionality,
// we don't remove process node if least one of its children nodes is alive.
// To avoid memory leak, we delete also all ancestors of the process that have no living children.
func (tree *ProcessTree) removeProcessFromTree(dpid int) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	// Make sure that the process is not deleted because missed children
	if !p.hasChildren() {
		tree.cleanProcess(p)
	}
}

// immediateRemoveProcessFromTree is the same as removeProcessFromTree, except it remove the
// process from the tree access (via getProcess method) immediately, regardless of its state.
// It will still remove the node from the tree only if all its children are dead.
func (tree *ProcessTree) immediateRemoveProcessFromTree(dpid int) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	tree.removeProcess(p)
	// Make sure that the process is not deleted because missed children
	if !p.hasChildren() {
		tree.cleanProcess(p)
	}
}

// deleteNodeAndDeadAncestors remove process and all dead ancestors so only processes
// which are alive or with living descendants will remain in the tree.
// All nodes removed this way are deleted - all references to them or from them are deleted.
// This should allow them to be garbage collected later on.
// This remove is recursive because of the GC LRU eviction function is calling it.
func (tree *ProcessTree) deleteNodeAndDeadAncestors(pn *processNode) {
	// TODO: Make this function atomic
	// TODO: Add a flag specifying that the node was cleaned, to avoid modification after cleaning
	tree.removeProcess(pn)
	pn.mutex.RLock()
	threads := pn.getThreads()
	parent := pn.getParent()
	pn.mutex.RUnlock()

	pn.DisconnectNode()
	for _, thread := range threads {
		tree.cleanThread(thread)
	}
	if parent == nil {
		return
	}
	parent.mutex.RLock()
	// If parent is still alive, or it has living children nodes, we don't want to delete it
	shouldCleanParent := parent.exited() && !parent.hasChildren()
	parent.mutex.RUnlock()
	if shouldCleanParent {
		tree.cleanProcess(parent)
	}
}
