package proctree

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// nodeUniqueId is a set of information which should be unique enough to identify a node from
// another at all cases.
type nodeUniqueId struct {
	id         int
	uniqueTime int
}

// gcNode is a node which support being cleaned from the process tree.
// All the nodes followed by the process tree has to implement this interface.
type gcNode interface {
	// GetUniqueId generates the unique ID to identify the node with in the tree.
	GetUniqueId() nodeUniqueId
	// DisconnectNode remove all references from the node to other nodes and vice versa.
	// There should be no connections to and from the node after this is called.
	DisconnectNode()
}

type ProcessTreeConfig struct {
	// Max amount of processes nodes to allow in memory.
	// Too small value here might result missing information in the tree and inconsistency.
	// Default recommended value is 32768, as this is the max amount of PIDs in the system.
	// You might even want more than 32768 to allow relevant information of dead processes to be
	// available after their exit.
	MaxProcesses int
	// Max amount of threads nodes to allow in memory.
	// Too small value here might result missing information in the tree and inconsistency.
	// Default recommended value is 32768, as this is the max amount of TIDs in the system.
	// You might even want more than 32768 to allow relevant information of dead threads to be
	// available after their exit.
	MaxThreads int
	// Max size of cache for processes removing after exit - translate to the delay between process
	// exit to its removal from the tree (if it is not interesting after its death).
	// Too small value here might result processes missing from tree after their exit, before
	// users were able to query the process information because of the delay between the feeding
	// of the tree and the consumption of its information.
	MaxCacheDelete int
}

// ProcessTree is a struct which follow the state of processes during runtime of a system.
// The process tree is updated through Tracee's events, and is designed to overcome problems that
// may arise because of events consumption (like handling lost events).
// For more information on the logic, please go to the package documentation.
type ProcessTree struct {
	processes          types.RWMap[int, *processNode]
	threads            types.RWMap[int, *threadNode]
	processesGC        *lru.Cache[nodeUniqueId, *processNode]
	threadsGC          *lru.Cache[nodeUniqueId, *threadNode]
	deadProcessesCache *lru.Cache[int, bool]
}

func NewProcessTree(config ProcessTreeConfig) (*ProcessTree, error) {
	tree := &ProcessTree{
		processes: types.InitRWMap[int, *processNode](),
		threads:   types.InitRWMap[int, *threadNode](),
	}
	cache, err := lru.NewWithEvict[int, bool](
		config.MaxCacheDelete,
		func(dpid int, _ bool) {
			tree.removeProcessFromTree(dpid)
		})
	if err != nil {
		return nil, err
	}
	processesGC, err := lru.NewWithEvict[nodeUniqueId, *processNode](
		config.MaxProcesses,
		func(id nodeUniqueId, node *processNode) {
			tree.deleteProcess(node)
		},
	)
	if err != nil {
		return nil, err
	}
	threadsGC, err := lru.NewWithEvict[nodeUniqueId, *threadNode](
		config.MaxThreads,
		func(id nodeUniqueId, node *threadNode) {
			tree.deleteThread(node)
		},
	)
	if err != nil {
		return nil, err
	}
	tree.deadProcessesCache = cache
	tree.processesGC = processesGC
	tree.threadsGC = threadsGC
	return tree, nil
}

// getProcess get the process node from the process tree if exists, and return error if not.
func (tree *ProcessTree) getProcess(hostProcessID int) (*processNode, error) {
	process, ok := tree.processes.Get(hostProcessID)
	if !ok {
		return nil, fmt.Errorf("no process with given Id is recorded")
	}
	_, _ = tree.processesGC.Get(process.GetUniqueId())
	return process, nil
}

// setProcess add the process node to the process tree
func (tree *ProcessTree) setProcess(pnode *processNode) error {
	tree.processes.Set(pnode.getId(), pnode)
	ok, _ := tree.processesGC.ContainsOrAdd(pnode.GetUniqueId(), pnode)
	// If exists, we want to update its last usage
	if ok {
		tree.processesGC.Get(pnode.GetUniqueId())
	}
	return nil
}

// hasProcess return if the process is accessible through the tree
func (tree *ProcessTree) hasProcess(hostProcessID int) bool {
	_, exist := tree.processes.Get(hostProcessID)
	return exist
}

// removeProcess remove the process node from the process tree
// This does not remove references to it from other nodes and vice versa, nor allow it to be
// garbage collected.
func (tree *ProcessTree) removeProcess(pnode *processNode) error {
	tree.processes.Delete(pnode.getId())
	return nil
}

// cleanProcess remove the process from the GC LRU, triggering cleaning eviction function
func (tree *ProcessTree) cleanProcess(pnode *processNode) error {
	_ = tree.processesGC.Remove(pnode.GetUniqueId())
	return nil
}

// deleteProcess remove the process node from the process tree and delete all references to it,
// so it could be garbage collected
func (tree *ProcessTree) deleteProcess(pnode *processNode) error {
	tree.deleteNodeAndDeadAncestors(pnode)
	return nil
}

// getThread get the thread node from the process tree if exists, and return error if not.
func (tree *ProcessTree) getThread(hostThreadId int) (*threadNode, error) {
	thread, ok := tree.threads.Get(hostThreadId)
	if !ok {
		return nil, fmt.Errorf("no thread with given Id is recorded")
	}
	_, _ = tree.threadsGC.Get(thread.GetUniqueId())
	return thread, nil
}

// setThread add the thread node to the process tree
func (tree *ProcessTree) setThread(tnode *threadNode) error {
	tree.threads.Set(tnode.getId(), tnode)
	ok, _ := tree.threadsGC.ContainsOrAdd(tnode.GetUniqueId(), tnode)
	// If exists, we want to update its last usage
	if ok {
		tree.threadsGC.Get(tnode.GetUniqueId())
	}
	return nil
}

// hasThread return if the thread is accessible through the tree
func (tree *ProcessTree) hasThread(hostThreadID int) bool {
	_, exist := tree.threads.Get(hostThreadID)
	return exist
}

// removeProcess remove the process node from the process tree
// This does not remove references to it from other nodes and vice versa, nor allow it to be
// garbage collected.
func (tree *ProcessTree) removeThread(tnode *threadNode) error {
	tree.threads.Delete(tnode.getId())
	return nil
}

// cleanThread remove the thread from the GC LRU, triggering cleaning eviction function
func (tree *ProcessTree) cleanThread(tnode *threadNode) error {
	_ = tree.threadsGC.Remove(tnode.GetUniqueId())
	return nil
}

// deleteThread remove the thread node from the process tree and delete all references to it,
// so it could be garbage collected
func (tree *ProcessTree) deleteThread(tnode *threadNode) error {
	_ = tree.removeThread(tnode)
	tnode.DisconnectNode()
	return nil
}

// addGeneralEventProcess generate a new process with information that could be received from any
// event from the process
func (tree *ProcessTree) addGeneralEventProcess(event *trace.Event) (*processNode, error) {
	process, err := tree.newProcessNode(event.HostProcessID)
	if err != nil {
		return nil, err
	}
	process.setGenInfoFromEventProtected(event)
	return process, nil
}

// addGeneralEventThread generate a new thread with information that could be received from any
// event from the thread
func (tree *ProcessTree) addGeneralEventThread(event *trace.Event) (*threadNode, error) {
	p, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		p, err = tree.addGeneralEventProcess(event)
		if err != nil {
			return nil, err
		}
	}
	p.mutex.Lock()
	thread, err := tree.newProcessThreadNode(p, event.HostThreadID)
	exitTime := p.getExitTime()
	p.mutex.Unlock()
	if err != nil {
		return nil, err
	}

	thread.setGenInfoFromEventProtected(event, exitTime)
	return thread, nil
}

// generateParentProcess add a parent process to given process from tree if existing or creates
// new node with the best effort info
func (tree *ProcessTree) generateParentProcess(parentHostId int, parentNsId int, process *processNode) (*processNode, error) {
	if parentNsId != 0 &&
		process.getId() != parentHostId { // Prevent looped references
		parentProcess, err := tree.getProcess(parentHostId)
		if err != nil {
			// TODO: Fix the race condition here between checking if exist and setting new one
			parentProcess, err = tree.newProcessNode(parentHostId)
			if err != nil {
				return nil, err
			}
			parentProcess.setNsId(parentNsId)
			if err != nil {
				return nil, err
			}
		}
		process.mutex.Lock()
		process.connectParent(parentProcess)
		process.mutex.Unlock()
		parentProcess.mutex.Lock()
		parentProcess.connectChild(process)
		parentProcess.mutex.Unlock()
	}
	return process, nil
}

// newProcessNode create a new processNode and sign it in the tree
func (tree *ProcessTree) newProcessNode(pid int) (*processNode, error) {
	proc, err := newProcessNode(pid)
	if err != nil {
		return nil, err
	}
	tree.processes.Set(pid, proc)
	tree.processesGC.Add(proc.GetUniqueId(), proc)
	return proc, nil
}

// newThreadNode create a new threadNode and sign it in the tree
func (tree *ProcessTree) newThreadNode(tid int) (*threadNode, error) {
	thread, err := newThreadNode(tid)
	if err != nil {
		return nil, err
	}
	tree.threads.Set(tid, thread)
	tree.threadsGC.Add(thread.GetUniqueId(), thread)
	return thread, nil
}

// newProcessThreadNode add a new thread to a process, and also sign the thread in the tree.
// It will return existing one if there is one with the same ID.
func (tree *ProcessTree) newProcessThreadNode(process *processNode, tid int) (*threadNode, error) {
	newThread, err := process.addThreadBasic(tid)
	if err != nil {
		return nil, err
	}
	err = tree.setThread(newThread)
	return newThread, err
}
