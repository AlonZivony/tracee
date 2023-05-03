package proctree

import (
	gocontext "context"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// GetProcessInfo return the process information from the process tree relevant to the given time
func (tree *ProcessTree) GetProcessInfo(hostProcessID int, time int) (ProcessInfo, error) {
	pn, err := tree.getProcess(hostProcessID)
	if err != nil {
		return ProcessInfo{}, err
	}
	return pn.export(time), nil
}

// GetProcessLineage return list of processes, starting with give PID process upward, of the ancestors of the process
// up to the last known ancestor or the container root.
// The information of all the processes is relevant to the given time
func (tree *ProcessTree) GetProcessLineage(hostProcessID int, time int) (ProcessLineage, error) {
	pList, err := tree.getProcessLineage(hostProcessID)
	if err != nil {
		return nil, err
	}
	lineage := make(ProcessLineage, len(pList))
	for i, p := range pList {
		lineage[i] = p.export(time)
	}
	return lineage, nil
}

// StartProcessingPipeline create a goroutine that feeds the process tree from the incoming events
func (tree *ProcessTree) StartProcessingPipeline(ctx gocontext.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
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

func (tree *ProcessTree) getProcess(hostProcessID int) (*processNode, error) {
	process, ok := tree.processes[hostProcessID]
	if !ok {
		return nil, fmt.Errorf("no process with given ID is recorded")
	}
	return process, nil
}

// getProcessLineage returns list of processes starting with the ID matching events back to the root of the container
// or oldest registered ancestor in the container (if root is missing)
func (tree *ProcessTree) getProcessLineage(hostProcessID int) ([]*processNode, error) {
	process, err := tree.getProcess(hostProcessID)
	if err != nil {
		return nil, err
	}
	var lineage []*processNode
	for process != nil {
		lineage = append(lineage, process)
		process = process.ParentProcess
	}
	return lineage, nil
}

// export return the process information true to the given time
func (p *processNode) export(time int) ProcessInfo {
	var childrenIDs []int
	var threadIDs []int
	for _, child := range p.ChildProcesses {
		if child.IsAlive ||
			time < int(child.ExitTime) {
			childrenIDs = append(childrenIDs, child.InHostIDs.Pid)
		}
	}
	for tid, threadExitTime := range p.Threads {
		if (threadExitTime.exitTime == 0 ||
			time < int(threadExitTime.exitTime)) && int(threadExitTime.forkTime) < time {
			threadIDs = append(threadIDs, tid)
		}
	}
	return ProcessInfo{
		NsIDs:           p.InContainerIDs,
		HostIDs:         p.InHostIDs,
		UserID:          p.UserID,
		Namespaces:      p.Namespaces,
		ContainerID:     p.ContainerID,
		ProcessName:     p.ProcessName,
		Cmd:             p.Cmd,
		ExecutionBinary: p.ExecutionBinary,
		StartTime:       int(p.StartTime),
		ExecTime:        int(p.ExecTime),
		ExitTime:        int(p.ExitTime),
		ExistingThreads: threadIDs,
		ChildrenIDs:     childrenIDs,
	}
}
