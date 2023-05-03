package proctree

import (
	"sync"

	"github.com/RoaringBitmap/roaring"

	"github.com/aquasecurity/tracee/pkg/utils/types"
)

// ProcessTree is a struct which follow the state of processes during runtime in container
// contexts.
// The process tree is updated through Tracee's events,
// and is designed to overcome problems that may arise because
// of events consumption (like handling lost events).
// It does so by doing its best effort to deduce from the coming events what might have been
// missed:
// * Deduce from all events information on their invoking processes,
// in case of missed fork/exec/exit.
// * Deducing from all event the connections between parent to children processes in case of
// missed forks.
// * Deduce that missed process exit event when finding new fork with the same PID (
// only PID reuse is hard to work with)
type ProcessTree struct {
	processes          types.RWMap[int, *processNode]
	deadProcessesCache []int
}

func InitProcessTree() *ProcessTree {
	return &ProcessTree{
		processes:          types.InitRWMap[int, *processNode](),
		deadProcessesCache: make([]int, 0),
	}
}

// ProcessInfo is the user facing representation of a process data at a specific time.
type ProcessInfo struct {
	NsIDs           ProcessIDs
	HostIDs         ProcessIDs
	UserID          int
	Namespaces      NamespacesIDs
	ContainerID     string
	ProcessName     string
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       int
	ExecTime        int
	ExitTime        int
	ExistingThreads []int
	ChildrenIDs     []int
}

func (p *ProcessInfo) IsAlive(time int) bool {
	return time < p.ExitTime
}

type ProcessIDs struct {
	Pid  int
	Ppid int
}

type BinaryInfo struct {
	Path   string
	Hash   string
	Inode  uint
	Device uint
	Ctime  uint
}

type NamespacesIDs struct {
	// TODO: Support all namespaces
	Pid   int
	Mount int
}

// ProcessLineage is a representation of a process and its ancestors until the oldest ancestor
// known in the tree.
// The lineage is only relevant for the container the process reside in.
type ProcessLineage []ProcessInfo

// processInformationStatus is the status of the information that was filled in the processNode
// up to this point.
// Its main use is to monitor what needs to be filled,
// and what to expect to be missing in the node.
type processInformationStatus uint32

const (
	forked processInformationStatus = iota
	executed
	generalCreated // Information that resides in every event
	hollowParent   // Information of parent process that resides in every event
)

type timestamp int

type processNode struct {
	// TODO: Add information about the processes like opened files,
	//  network activities (like TCP connections), argv, environment variables,
	//  loader and interpreter
	InContainerIDs ProcessIDs
	InHostIDs      ProcessIDs
	UserID         int
	Namespaces     NamespacesIDs
	ContainerID    string
	ProcessName    string // TODO: Support following process name according to timestamp (
	// if changed)
	Cmd             []string
	ExecutionBinary BinaryInfo
	StartTime       timestamp
	ExecTime        timestamp
	ExitTime        timestamp
	ParentProcess   *processNode
	ChildProcesses  []*processNode
	Threads         types.RWMap[int, *threadInfo]
	IsAlive         bool
	Status          roaring.Bitmap // Values type are processInformationStatus
	Mutex           sync.RWMutex
}

type threadInfo struct {
	forkTime timestamp
	exitTime timestamp
}

type containerProcessTree struct {
	Root *processNode
}
