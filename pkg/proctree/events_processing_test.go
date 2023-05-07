package proctree

import (
	"github.com/aquasecurity/tracee/pkg/utils/types"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/types/trace"
)

const TestContainerID = "a7f965fba4e145e02c99b1577febe0cb723a943d850278365994ac9b0190540e"

func TestProcessTree_ProcessEvent(t *testing.T) {
	pid := 22482
	ppid := 22447
	tid := pid + 1
	forkTimestamp := 1639044471927303690
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := uint(1625759227634052514)

	processForkEvent := trace.Event{
		Timestamp:           forkTimestamp,
		ProcessID:           ppid,
		ThreadID:            ppid,
		ParentProcessID:     22422,
		HostProcessID:       ppid,
		HostThreadID:        ppid,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerID},
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(pid)},
		},
	}
	execEvent := trace.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerID},
		EventID:             1003,
		EventName:           "sched_process_exec",
		ArgsNum:             9,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "cmdpath", Type: "const char*"}, Value: interface{}("/bin/ls")},
			{ArgMeta: trace.ArgMeta{Name: "argv", Type: "const char**"}, Value: interface{}(execCmd)},
			{ArgMeta: trace.ArgMeta{Name: "env", Type: "const char**"}, Value: interface{}([]string{"HOSTNAME=aac1fa454fcd", "SHLVL=1", "HOME=/root", "TERM=xterm", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD=/"})},
			{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "const char*"}, Value: interface{}(execBinaryPath)},
			{ArgMeta: trace.ArgMeta{Name: "dev", Type: "dev_t"}, Value: interface{}(uint32(46))},
			{ArgMeta: trace.ArgMeta{Name: "inode", Type: "unsigned long"}, Value: interface{}(uint64(576807))},
			{ArgMeta: trace.ArgMeta{Name: "invoked_from_kernel", Type: "int"}, Value: interface{}(0)},
			{ArgMeta: trace.ArgMeta{Name: "ctime", Type: "unsigned long"}, Value: interface{}(uint64(execBinaryCtime))},
			{ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"}, Value: interface{}("abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527")},
		},
	}
	threadForkEvent := trace.Event{
		Timestamp:           1639044471927556767,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerID},
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(tid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(pid)},
		},
	}
	threadExitEvent := trace.Event{
		Timestamp:           1639044471928003089,
		ProcessID:           pid,
		ThreadID:            tid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        tid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerID},
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             2,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: false},
		},
	}
	processExitEvent := trace.Event{
		Timestamp:           1639044471928009089,
		ProcessID:           pid,
		ThreadID:            pid,
		ParentProcessID:     ppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "ls",
		HostName:            "aac1fa476fcd",
		Container:           trace.Container{ID: TestContainerID},
		EventID:             1004,
		EventName:           "sched_process_exit",
		ArgsNum:             2,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "exit_code", Type: "long"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Name: "process_group_exit", Type: "bool"}, Value: true},
		},
	}

	checkProcessForksInfo := func(t *testing.T, p *processNode, forkTime int, exitTime int) {
		assert.Equal(t, timestamp(forkTimestamp), p.StartTime)
		thread, ok := p.Threads.Get(pid)
		assert.True(t, ok, "thread", pid)
		assert.Equal(t, timestamp(exitTime), thread.exitTime)
		assert.Equal(t, timestamp(forkTime), thread.forkTime)
	}
	checkMissingProcessForkInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, timestamp(0), p.StartTime)
		thread, ok := p.Threads.Get(pid)
		assert.True(t, ok, "thread", pid)
		assert.Equal(t, timestamp(0), thread.exitTime)
		assert.Equal(t, timestamp(0), thread.forkTime)
	}
	checkThreadForkInfo := func(t *testing.T, p *processNode, forkTime int, exitTime int) {
		require.Contains(t, p.Threads.Keys(), tid)
		thread, ok := p.Threads.Get(tid)
		assert.True(t, ok, "thread", tid)
		assert.Equal(t, timestamp(exitTime), thread.exitTime)
		assert.Equal(t, timestamp(forkTime), thread.forkTime)
	}
	checkGeneralInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, pid, p.InHostIDs.Pid)
		assert.Equal(t, ppid, p.InHostIDs.Ppid)
	}
	checkExecInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, execCmd, p.Cmd)
		assert.Equal(t, execBinaryPath, p.ExecutionBinary.Path)
		assert.Equal(t, execBinaryCtime, p.ExecutionBinary.Ctime)
		assert.Equal(t, timestamp(execEvent.Timestamp), p.ExecTime)
	}
	checkNotExecedInfo := func(t *testing.T, p *processNode) {
		assert.Equal(t, []string(nil), p.Cmd)
		assert.Equal(t, "", p.ExecutionBinary.Path)
		assert.Equal(t, uint(0), p.ExecutionBinary.Ctime)
		assert.Equal(t, "", p.ExecutionBinary.Hash)
	}
	checkProcessExitInfo := func(t *testing.T, p *processNode) {
		thread, ok := p.Threads.Get(pid)
		assert.True(t, ok, "thread", pid)
		assert.Equal(t, timestamp(processExitEvent.Timestamp), thread.exitTime)
	}
	checkThreadExitInfo := func(t *testing.T, p *processNode) {
		thread, ok := p.Threads.Get(tid)
		assert.True(t, ok, "thread", tid)
		assert.Equal(t, timestamp(threadExitEvent.Timestamp), thread.exitTime)
	}
	checkProcessExitSuccess := func(t *testing.T, tree *ProcessTree) {
		tree.emptyDeadProcessesCache()
		_, err := tree.getProcess(pid)
		assert.Error(t, err)
	}

	t.Run("Ordered flows", func(t *testing.T) {
		t.Run("Ordered normal flow", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Ordered main thread exit first", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			// Switch between the exit events order for this test
			var modifiedProcessExitEvent, modifiedThreadExitEvent trace.Event
			modifiedProcessExitEvent = processExitEvent
			modifiedProcessExitEvent.Args = make([]trace.Argument, 2)
			copy(modifiedProcessExitEvent.Args, processExitEvent.Args)
			modifiedProcessExitEvent.Args[1].Value = interface{}(false)
			modifiedThreadExitEvent = threadExitEvent
			modifiedThreadExitEvent.Args = make([]trace.Argument, 2)
			copy(modifiedThreadExitEvent.Args, threadExitEvent.Args)
			modifiedThreadExitEvent.Args[1].Value = interface{}(true)
			modifiedProcessExitEvent.Timestamp, modifiedThreadExitEvent.Timestamp = modifiedThreadExitEvent.Timestamp, modifiedProcessExitEvent.Timestamp

			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			require.NoError(t, tree.ProcessEvent(&modifiedProcessExitEvent))
			mainThread, ok := process.Threads.Get(pid)
			require.True(t, ok, "thread", pid)
			assert.Equal(t, timestamp(modifiedProcessExitEvent.Timestamp), mainThread.exitTime)
			require.NoError(t, tree.ProcessEvent(&modifiedThreadExitEvent))
			forkedThread, ok := process.Threads.Get(tid)
			require.True(t, ok, "thread", tid)
			assert.Equal(t, timestamp(modifiedThreadExitEvent.Timestamp), forkedThread.exitTime)
			checkProcessExitSuccess(t, &tree)
		})
	})
	t.Run("Unordered events flows", func(t *testing.T) {
		t.Run("Unordered exec before main fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkExecInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered fork thread before main fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered exit thread before thread fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, threadExitEvent.Timestamp)
			checkExecInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Unordered exit main thread before process fork", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, processExitEvent.Timestamp)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			err = tree.ProcessEvent(&threadExitEvent)
			require.NoError(t, err)
			checkThreadExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
	})
	t.Run("Missing event flow", func(t *testing.T) {
		t.Run("Missing main fork event", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkMissingProcessForkInfo(t, process)
			checkExecInfo(t, process)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing exec event", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkNotExecedInfo(t, process)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing thread fork event", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			assert.NotContains(t, process.Threads.Keys(), tid)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing thread exit", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&processExitEvent))
			checkProcessExitInfo(t, process)
			forkedThread, ok := process.Threads.Get(tid)
			require.True(t, ok, "thread", tid)
			assert.Equal(t, timestamp(processExitEvent.Timestamp), forkedThread.exitTime)
			checkProcessExitSuccess(t, &tree)
		})
		t.Run("Missing main thread exit", func(t *testing.T) {
			tree := ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			}
			var err error
			require.NoError(t, tree.ProcessEvent(&processForkEvent))
			require.NoError(t, tree.ProcessEvent(&execEvent))
			require.NoError(t, tree.ProcessEvent(&threadForkEvent))
			process, err := tree.getProcess(pid)
			assert.NoError(t, err)
			checkGeneralInfo(t, process)
			checkProcessForksInfo(t, process, processForkEvent.Timestamp, 0)
			checkThreadForkInfo(t, process, threadForkEvent.Timestamp, 0)
			checkExecInfo(t, process)
			require.NoError(t, tree.ProcessEvent(&threadExitEvent))
			checkThreadExitInfo(t, process)
			mainThread, ok := process.Threads.Get(pid)
			require.True(t, ok, "thread", pid)
			assert.Equal(t, timestamp(0), mainThread.exitTime)
			tree.emptyDeadProcessesCache()
			process, err = tree.getProcess(pid)
			assert.NoError(t, err)
			assert.Contains(t, process.Threads.Keys(), pid)
		})
	})
}
