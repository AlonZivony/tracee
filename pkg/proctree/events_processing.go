package proctree

import (
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessEvent update the process tree according to arriving event
func (tree *ProcessTree) ProcessEvent(traceeEvent *trace.Event) error {
	switch traceeEvent.EventName {
	case "sched_process_fork":
		return tree.processForkEvent(traceeEvent)
	case "sched_process_exec":
		return tree.processExecEvent(traceeEvent)
	case "sched_process_exit":
		return tree.processExitEvent(traceeEvent)
	case "exit", "init_namespaces":
		return nil
	default:
		return tree.processDefaultEvent(traceeEvent)
	}
}

// processDefaultEvent tries to expand the process tree in case of lost events or missing general information
func (tree *ProcessTree) processDefaultEvent(event *trace.Event) error {
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
		process.addThread(event.HostThreadID)
	} else if process.Status.Contains(uint32(hollowParent)) {
		fillHollowParentProcessGeneralEvent(process, event)
	}
	process.addThread(event.HostThreadID)
	if process.ParentProcess == nil {
		tree.generateParentProcess(process)
	}
	return nil
}
