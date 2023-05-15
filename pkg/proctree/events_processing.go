package proctree

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessEvent update the process tree according to arriving event
func (tree *ProcessTree) ProcessEvent(traceeEvent *trace.Event) error {
	switch events.ID(traceeEvent.EventID) {
	case events.SchedProcessFork:
		return tree.processForkEvent(traceeEvent)
	case events.SchedProcessExec:
		return tree.processExecEvent(traceeEvent)
	case events.SchedProcessExit:
		return tree.processExitEvent(traceeEvent)
	case events.Exit, events.InitNamespaces, events.HiddenKernelModule:
		return nil
	default:
		return tree.processDefaultEvent(traceeEvent)
	}
}

// processDefaultEvent tries to expand the process tree in case of lost events or missing general
// information
func (tree *ProcessTree) processDefaultEvent(event *trace.Event) error {
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		process = tree.addGeneralEventProcess(event)
	}
	if process.Status.Contains(uint32(hollowParent)) &&
		!process.Status.Contains(uint32(generalCreated)) {
		process.fillGeneralInfoForHollowByEvent(event)
	}
	process.addGeneralEventThread(event)
	if process.ParentProcess == nil {
		tree.generateParentProcess(process)
	}
	return nil
}
