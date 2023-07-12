package proctree

import (
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

// processNode is a node in the process tree representing a process.
// Its purpose is to keep the information of the process, and the connections to other processes
// and threads nodes.
// The current implementation is using mutex, so all internal members are assumed to be protected
// by it (so are not necessarily thread-safe types)
type processNode struct {
	// TODO: Add information about the processes like opened files,
	//  network activities (like TCP connections), argv, environment variables,
	//  loader and interpreter
	id             int
	creationTime   int
	nsId           int
	userId         int
	containerId    string
	genInfoLock    sync.Once
	execInfo       *types.ChangingObj[procExecInfo]
	forkTime       types.Timestamp
	exitTime       types.Timestamp
	parentProcess  *processNode
	childProcesses map[int]*processNode
	threads        map[int]*threadNode
	mutex          sync.RWMutex // Protection on all accesses to the process, except for PID reading
}

// procExecInfo is the information about a process which is changed upon execution
type procExecInfo struct {
	Cmd             []string
	ExecutionBinary FileInfo
}

func newProcessNode(id int) (*processNode, error) {
	return &processNode{
		id:             id,
		creationTime:   int(time.Now().UnixNano()),
		threads:        make(map[int]*threadNode),
		childProcesses: make(map[int]*processNode),
		execInfo:       types.NewChangingObj[procExecInfo](procExecInfo{}),
	}, nil

}

// setGenInfoFromEventProtected fill the general info of the process (information
// of the event given by every process received from it) in a way that it is filled
// only once in an efficient way to reduce performance penalty.
// This method uses the process lock to reduce unnecessary locking if not needed. Make sure to unlock
// the lock before using this.
func (p *processNode) setGenInfoFromEventProtected(event *trace.Event) {
	p.genInfoLock.Do(
		func() {
			p.mutex.Lock()
			p.fillGeneralInfo(
				event.ProcessID,
				event.UserID,
				event.ContainerID,
			)
			p.mutex.Unlock()
		},
	)
}

// setGeneralInfoProtected is used to fill general information of a process
// only once, but when the information cannot be retrieved from an event like
// with setGenInfoFromEventProtected.
// This method is not protected by locks.
func (p *processNode) setGeneralInfoProtected(
	nsPid int,
	userId int,
	containerId string,
) {
	p.genInfoLock.Do(
		func() {
			p.fillGeneralInfo(
				nsPid,
				userId,
				containerId,
			)
		},
	)
}

// fillGeneralInfo is a util function to fill general information in process node.
// General information is an information that resides in every event from a process.
// As such, this information should only be updated once (unless it is changeable).
func (p *processNode) fillGeneralInfo(
	nsPid int,
	userId int,
	containerId string,
) {
	p.setUserId(userId)
	p.setContainerId(containerId)
	p.setNsId(nsPid)
}

// addThreadBasic add the thread to the process node if it does not exist.
// The function also tries to synchronize the thread exit time with the process if filled after
// process exit.
// This function *does not* add the thread to the process tree, so it should be added afterward.
func (p *processNode) addThreadBasic(tid int) (*threadNode, error) {
	t, exist := p.getThread(tid)
	if exist {
		return t, nil
	}
	var err error
	t, err = newThreadNode(tid)
	if err != nil {
		return nil, err
	}
	// Update thread exit time to match process if process exited
	t.setExitTime(p.getExitTime())
	t.connectToProcess(p)
	p.connectToThread(t)
	return t, nil
}

// isAlive return if the process is alive at the given moment, according to existing information
// of the node.
func (p *processNode) isAlive(time types.Timestamp) bool {
	exitTime := p.getExitTime()
	if exitTime == 0 {
		return true
	}
	if time >= exitTime {
		return false
	}
	forkTime := p.getForkTime()
	if time >= forkTime {
		return true
	}
	return false
}

// setExitTime sets the process's exit time
func (p *processNode) setExitTime(exitTime types.Timestamp) {
	p.exitTime = exitTime
}

// setDefaultExitTime sets the process's exit time if it's not initialized
func (p *processNode) setDefaultExitTime(exitTime types.Timestamp) {
	if p.exitTime == 0 {
		p.exitTime = exitTime
	}
}

// exited return if the process exit was received
func (p *processNode) exited() bool {
	return p.getExitTime() != 0
}

// getExitTime return the process's exit time
func (p *processNode) getExitTime() types.Timestamp {
	return p.exitTime
}

// setForkTime sets the process's fork time
func (p *processNode) setForkTime(forkTime types.Timestamp) {
	p.forkTime = forkTime
}

// setDefaultForkTime sets the process's fork time if it's not initialized
func (p *processNode) setDefaultForkTime(forkTime types.Timestamp) {
	if p.forkTime == 0 {
		p.forkTime = forkTime
	}
}

// getForkTime return the process's fork time
func (p *processNode) getForkTime() types.Timestamp {
	return p.forkTime
}

// fillExecInfo add execution information to the process from raw format
func (p *processNode) fillExecInfo(
	binary FileInfo,
	cmd []string,
	execTime types.Timestamp,
) {
	p.setExecInfo(
		execTime, procExecInfo{
			Cmd:             cmd,
			ExecutionBinary: binary,
		},
	)
}

// setExecInfo add execution information to the process
func (p *processNode) setExecInfo(time types.Timestamp, info procExecInfo) {
	execState := types.State[procExecInfo]{
		StartTime: time,
		Val:       info,
	}
	p.execInfo.AddState(execState)
}

// setDefaultExecInfo change the execution information assumed for the process before its first
// execution received.
func (p *processNode) setDefaultExecInfo(info procExecInfo) {
	p.execInfo.ChangeDefault(info)
}

// getExecInfo return the execution information relevant to given time
func (p *processNode) getExecInfo(time types.Timestamp) procExecInfo {
	return p.execInfo.Get(time)
}

// getExecTime return the last execution time before the given one
func (p *processNode) getExecTime(time types.Timestamp) types.Timestamp {
	state := p.execInfo.GetState(time)
	return state.StartTime
}

// disconnectFromParent remove reference to parent process
func (p *processNode) disconnectFromParent() {
	p.parentProcess = nil
}

// disconnectFromThreads remove the references to all the threads
func (p *processNode) disconnectFromThreads() {
	maps.Clear(p.threads)
}

// disconnectChild remove reference to given child
func (p *processNode) disconnectChild(childToDisconnect *processNode) {
	delete(p.childProcesses, childToDisconnect.getId())
}

// connectParent add given process as the parent process of the current one
func (p *processNode) connectParent(parent *processNode) {
	p.parentProcess = parent
}

// connectChild add given process as the child process of the current one
func (p *processNode) connectChild(child *processNode) {
	p.childProcesses[child.getId()] = child
}

// This doesn't have to be protected by mutex, as the process Id shouldn't change after creation
func (p *processNode) getId() int {
	return p.id
}

// getNsId return the PID of the process in its PID namespace
func (p *processNode) getNsId() int {
	return p.nsId
}

// setNsId set the PID of the process in its namespace to given one
func (p *processNode) setNsId(nsId int) {
	p.nsId = nsId
}

// getContainerId return the ID of the container in which the process resides
func (p *processNode) getContainerId() string {
	return p.containerId
}

// setContainerId set the ID of the container in which the process resides
func (p *processNode) setContainerId(containerId string) {
	p.containerId = containerId
}

// getUserId return the ID of the user owning the process
func (p *processNode) getUserId() int {
	return p.userId
}

// setUserId set the ID of the user owning the process
func (p *processNode) setUserId(userId int) {
	p.userId = userId
}

// getThread return the thread with given TID if is a registered thread of the process
func (p *processNode) getThread(tid int) (*threadNode, bool) {
	thread, ok := p.threads[tid]
	return thread, ok
}

// connectToThread add reference to given thread as a thread of the current process
func (p *processNode) connectToThread(thread *threadNode) {
	p.threads[thread.getId()] = thread
}

// disconnectThread remove the reference to given thread from the current process
func (p *processNode) disconnectThread(thread *threadNode) {
	delete(p.threads, thread.getId())
}

// getThreads return all the registered threads of current process
func (p *processNode) getThreads() []*threadNode {
	return maps.Values(p.threads)
}

// getThreadsIds return the TIDs of all registered thread of current process
func (p *processNode) getThreadsIds() []int {
	return maps.Keys(p.threads)
}

// getChild return the child process with given PID if registered as a child of the current process
func (p *processNode) getChild(pid int) (*processNode, bool) {
	child, ok := p.childProcesses[pid]
	return child, ok
}

// getChildren return all registered children processes of current process
func (p *processNode) getChildren() []*processNode {
	return maps.Values(p.childProcesses)
}

// amountOfChildren return the amount of processes registered as children of current process
func (p *processNode) amountOfChildren() int {
	return len(p.childProcesses)
}

// hasChildren return if the current process has children registered to it
func (p *processNode) hasChildren() bool {
	return p.amountOfChildren() != 0
}

// getParent return the parent process of current one if one was registered
func (p *processNode) getParent() *processNode {
	return p.parentProcess
}

// GetUniqueId return a unique ID to identify the process by
func (p *processNode) GetUniqueId() nodeUniqueId {
	return nodeUniqueId{
		id:         p.getId(),
		uniqueTime: p.creationTime,
	}
}

// DisconnectNode remove all references from current node to other nodes, and vice versa
func (p *processNode) DisconnectNode() {
	p.mutex.RLock()
	threads := p.getThreads()
	parent := p.getParent()
	children := p.getChildren()
	p.mutex.RUnlock()

	p.mutex.Lock()
	p.disconnectFromParent()
	p.disconnectFromThreads()
	p.disconnectFromThreads()
	p.mutex.Unlock()

	if parent != nil {
		parent.mutex.Lock()
		parent.disconnectChild(p)
		parent.mutex.Unlock()
	}

	for _, childProcess := range children {
		childProcess.mutex.RLock()
		childParentProcess := childProcess.getParent()
		childProcess.mutex.RUnlock()
		if childParentProcess == p {
			childProcess.mutex.Lock()
			childProcess.disconnectFromParent()
			childProcess.mutex.Unlock()
		}
	}

	for _, thread := range threads {
		thread.mutex.Lock()
		thread.disconnectFromProcess()
		thread.mutex.Unlock()
	}
}
