package proctree

import (
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// processExitEvent remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit (but is limited to the
// possible number of PIDs - 32768)
func (tree *ProcessTree) processExitEvent(event *trace.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}
	process, _ := tree.getProcess(event.HostProcessID)
	thread := process.Threads[event.HostThreadID]
	if thread == nil {
		thread = &threadInfo{}
	}
	thread.exitTime = timestamp(event.Timestamp)
	process.Threads[event.HostThreadID] = thread

	processGroupExit, err := helpers.GetTraceeBoolArgumentByName(*event, "process_group_exit")
	if err != nil {
		return err
	}

	if processGroupExit {
		process.IsAlive = false
		process.ExitTime = timestamp(event.Timestamp)
		for tid, times := range process.Threads {
			if times.exitTime == 0 {
				process.Threads[tid].exitTime = timestamp(event.Timestamp)
			}
		}
		tree.cachedDeleteProcess(process.InHostIDs.Pid)
	}
	return nil
}

const cachedDeadEvents = 100

func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		tree.deleteProcessFromTree(dpid)
	}
}

func (tree *ProcessTree) emptyDeadProcessesCache() {
	for _, dpid := range tree.deadProcessesCache {
		tree.deleteProcessFromTree(dpid)
	}
	tree.deadProcessesCache = []int{}
}

func (tree *ProcessTree) deleteProcessFromTree(dpid int) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	// Make sure that the process is not deleted because missed children
	if len(p.ChildProcesses) == 0 {
		// Remove process and all dead ancestors so only processes which are alive or with living descendants will remain.
		cp := p
		for {
			delete(tree.processes, cp.InHostIDs.Pid)
			if cp.ParentProcess == nil {
				break
			}
			for i, childProcess := range cp.ParentProcess.ChildProcesses {
				if childProcess == cp {
					cp.ParentProcess.ChildProcesses = append(cp.ParentProcess.ChildProcesses[:i],
						cp.ParentProcess.ChildProcesses[i+1:]...)
					break
				}
			}
			if cp.ParentProcess.IsAlive {
				break
			}
			cp = cp.ParentProcess
		}
	}
}
