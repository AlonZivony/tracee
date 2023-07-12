package proctree

import (
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

type threadNode struct {
	id           int
	creationTime int
	nsId         int
	name         *types.ChangingObj[string]
	forkTime     types.Timestamp
	exitTime     types.Timestamp
	namespaces   NamespacesIds
	process      *processNode
	mutex        sync.RWMutex // Protection on all accesses to the thread, except for TID reading
	genInfoLock  sync.Once
}

// newThreadNode creates a new threadNode instance, with initialized values where needed.
func newThreadNode(tid int) (*threadNode, error) {
	return &threadNode{
		id:           tid,
		creationTime: int(time.Now().UnixNano()),
		name:         types.NewChangingObj[string](""),
	}, nil
}

// disconnectFromProcess remove the reference to the thread's processNode
func (t *threadNode) disconnectFromProcess() {
	t.process = nil
}

// connectToProcess add a processNode as the process of the thread.
func (t *threadNode) connectToProcess(proc *processNode) {
	t.process = proc
}

// getProcess return the thread's process
func (t *threadNode) getProcess() *processNode {
	return t.process
}

// isAlive return if the thread is alive at the given moment, according to existing information
// of the node.
func (t *threadNode) isAlive(time types.Timestamp) bool {
	exitTime := t.getExitTime()
	if exitTime == 0 {
		return true
	}
	if time >= exitTime {
		return false
	}
	forkTime := t.getForkTime()
	if time >= forkTime {
		return true
	}
	return false
}

// setGenInfoFromEventProtected fill the general info of the thread (information
// of the thread given by every event received from it) in a way that it is filled
// only once in an efficient way to reduce performance penalty.
// This method uses the thread lock to reduce unnecessary locking if not needed. Make sure to unlock
// the lock before using this.
func (t *threadNode) setGenInfoFromEventProtected(
	event *trace.Event,
	defaultExitTime types.Timestamp,
) {
	t.genInfoLock.Do(
		func() {
			t.mutex.Lock()
			t.fillGeneralInfo(
				event.ThreadID,
				event.ProcessName,
				NamespacesIds{
					Pid:   event.PIDNS,
					Mount: event.MountNS,
				},
				defaultExitTime,
			)
			t.mutex.Unlock()
		},
	)
}

// setGeneralInfoProtected is used to fill general information of a thread
// only once, but when the information cannot be retrieved from an event like
// with setGenInfoFromEventProtected.
// This method is not protected by locks.
func (t *threadNode) setGeneralInfoProtected(
	nsTid int,
	name string,
	namespaces NamespacesIds,
	defaultExitTime types.Timestamp,
) {
	t.genInfoLock.Do(
		func() {
			t.fillGeneralInfo(
				nsTid,
				name,
				namespaces,
				defaultExitTime,
			)
		},
	)
}

// fillGeneralInfo is a util function to fill general information in thread node.
// General information is an information that resides in every event from a thread.
// As such, this information should only be updated once (unless it is changeable).
func (t *threadNode) fillGeneralInfo(
	nsTid int,
	name string,
	namespaces NamespacesIds,
	defaultExitTime types.Timestamp,
) {
	t.setNsId(nsTid)
	t.setDefaultName(name)
	t.setNamespaces(namespaces)
	t.setDefaultExitTime(defaultExitTime)
}

// getId return the TID of the thread in the host.
// This doesn't have to be protected by mutex, as the process Id shouldn't change after creation
func (t *threadNode) getId() int {
	return t.id
}

// getNsId return the TID of the thread in its PID namespace.
func (t *threadNode) getNsId() int {
	return t.nsId
}

// setNsId set the TID of the thread in its PID namespace to the given one.
func (t *threadNode) setNsId(nsId int) {
	t.nsId = nsId
}

// setExitTime sets the thread's exit time
func (t *threadNode) setExitTime(exitTime types.Timestamp) {
	t.exitTime = exitTime
}

// setDefaultExitTime sets the thread's exit time if it's not initialized
func (t *threadNode) setDefaultExitTime(exitTime types.Timestamp) {
	if t.exitTime == 0 {
		t.setExitTime(exitTime)
	}
}

// getExitTime return the thread's exit time
func (t *threadNode) getExitTime() types.Timestamp {
	return t.exitTime
}

// setForkTime sets the thread's fork time
func (t *threadNode) setForkTime(forkTime types.Timestamp) {
	t.forkTime = forkTime
}

// setDefaultForkTime sets the thread's fork time if it's not initialized
func (t *threadNode) setDefaultForkTime(forkTime types.Timestamp) {
	if t.forkTime == 0 {
		t.setForkTime(forkTime)
	}
}

// getForkTime return the thread's fork time
func (t *threadNode) getForkTime() types.Timestamp {
	return t.forkTime
}

// getName return the thread's name, as it was at a given time.
// As a thread can change its name, by execve or prctl syscalls for example, the time of request
// is necessary.
func (t *threadNode) getName(time types.Timestamp) string {
	return t.name.Get(time)
}

// setName change the name of the thread to a new one starting from a given time.
func (t *threadNode) setName(time types.Timestamp, name string) {
	nameState := types.State[string]{
		StartTime: time,
		Val:       name,
	}
	t.name.AddState(nameState)
}

// setDefaultName change the name of the thread for any time in which it was not set until now.
// For example, if a thread's name changed after execution to "ls" in time 50, and its default
// name was set to "bash", for any time before 50 (for example, 42) it will still be considered
// "bash". For any time after 50, it will be considered "ls".
func (t *threadNode) setDefaultName(name string) {
	t.name.ChangeDefault(name)
}

// getNamespaces return all the namespaces of the threads.
func (t *threadNode) getNamespaces() NamespacesIds {
	return t.namespaces
}

// setNamespaces set the thread's namespaces
func (t *threadNode) setNamespaces(namespaces NamespacesIds) {
	t.namespaces = namespaces
}

// GetUniqueId return a unique ID to identify the node with, even if another thread node has the
// same TID as it.
func (t *threadNode) GetUniqueId() nodeUniqueId {
	return nodeUniqueId{
		id:         t.getId(),
		uniqueTime: t.creationTime,
	}
}

// DisconnectNode disconnect the thread from the process and vice versa.
// Notice that this is the only method locking the mutex, because it fulfills the gcNode interface.
func (t *threadNode) DisconnectNode() {
	t.mutex.Lock()
	proc := t.getProcess()
	if proc != nil {
		proc.mutex.Lock()
		proc.disconnectThread(t)
		proc.mutex.Unlock()
	}
	t.disconnectFromProcess()
	t.mutex.Unlock()
}
