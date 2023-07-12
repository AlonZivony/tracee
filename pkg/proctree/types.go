package proctree

// ProcessInfo is the user facing representation of a process data at a specific time.
type ProcessInfo struct {
	Id              int
	NsId            int
	Ppid            int
	NsPpid          int // TODO: is this redundant?
	UserId          int
	ContainerId     string
	Cmd             []string
	ExecutionBinary FileInfo
	StartTime       int // First thread fork time. TODO: Can we use the mian thread start time instead?
	ExecTime        int // Last execve call time
	ExitTime        int
	ExistingThreads []int
	ChildrenIds     []int
	IsAlive         bool
}

// ThreadInfo is the user facing representation of a thread data at a specific time.
type ThreadInfo struct {
	HostId        int
	NsId          int
	HostProcessID int
	ForkTime      int
	ExitTime      int
	Namespaces    NamespacesIds
	Name          string
	IsAlive       bool
}

type FileInfo struct {
	Path   string
	Hash   string // TODO: should we call it SHA256 or Hash?
	Inode  uint
	Device uint
	Ctime  uint
}

type NamespacesIds struct {
	// TODO: Support all namespaces
	Pid   int
	Mount int
}

// ProcessLineage is a representation of a process and its ancestors until the oldest ancestor
// known in the tree.
// The lineage is only relevant for the container the process reside in.
type ProcessLineage []ProcessInfo
