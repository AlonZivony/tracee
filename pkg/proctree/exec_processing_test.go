package proctree

import (
	"testing"

	"github.com/RoaringBitmap/roaring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestProcessTree_ProcessExec(t *testing.T) {
	execCmd := []string{"ls"}
	execBinaryPath := "/bin/busybox"
	execBinaryCtime := 1625759227634052514
	execBinaryHash := "abfd081fd7fad08d4743443061a12ebfbd25e3c5e446441795d472c389444527"
	execEvent := trace.Event{
		Timestamp:           1639044471927556667,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     0,
		HostProcessID:       22482,
		HostThreadID:        22482,
		HostParentProcessID: 22447,
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
			{ArgMeta: trace.ArgMeta{Name: "sha256", Type: "const char*"}, Value: interface{}(execBinaryHash)},
		},
	}
	testCases := []struct {
		testName        string
		initialTree     ProcessTree
		expectedProcess *processNode
	}{
		{
			testName: "empty tree",
			initialTree: ProcessTree{
				processes: types.InitRWMap[int, *processNode](),
			},
			expectedProcess: &processNode{
				InHostIDs: ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ProcessName: execEvent.ProcessName,
				Cmd:         execCmd,
				ExecutionBinary: BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
					Hash:  execBinaryHash,
				},
				ContainerID: TestContainerID,
				StartTime:   0,
				Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(executed)),
			},
		},
		{
			testName: "forked event executed",
			initialTree: ProcessTree{
				processes: types.EnvelopeMapWithRW[int, *processNode](map[int]*processNode{
					execEvent.HostProcessID: {
						InHostIDs: ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "bash",
						Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(forked)),
						Threads: types.EnvelopeMapWithRW[int, *threadInfo](map[int]*threadInfo{
							execEvent.HostProcessID: {},
						}),
					},
				}),
			},
			expectedProcess: &processNode{
				InHostIDs: ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				Cmd: execCmd,
				ExecutionBinary: BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
					Hash:  execBinaryHash,
				},
				ContainerID: TestContainerID,
				StartTime:   100000000,
				Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "Double execve process",
			initialTree: ProcessTree{
				processes: types.EnvelopeMapWithRW[int, *processNode](map[int]*processNode{
					execEvent.HostProcessID: {
						InHostIDs: ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						StartTime:   100000000,
						ProcessName: "sleep",
						Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
						ExecutionBinary: BinaryInfo{
							Path:  "/bin/sleep",
							Ctime: 100,
						},
						Threads: types.EnvelopeMapWithRW[int, *threadInfo](map[int]*threadInfo{
							execEvent.HostProcessID: {},
						}),
					},
				}),
			},
			expectedProcess: &processNode{
				InHostIDs: ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
					Hash:  execBinaryHash,
				},
				StartTime:   100000000,
				Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
		{
			testName: "General event generate process",
			initialTree: ProcessTree{
				processes: types.EnvelopeMapWithRW[int, *processNode](map[int]*processNode{
					execEvent.HostProcessID: {
						InHostIDs: ProcessIDs{
							Pid:  execEvent.HostProcessID,
							Ppid: execEvent.HostParentProcessID,
						},
						InContainerIDs: ProcessIDs{
							Pid:  execEvent.ProcessID,
							Ppid: execEvent.ParentProcessID,
						},
						ContainerID: TestContainerID,
						ProcessName: execEvent.ProcessName,
						Status:      *roaring.BitmapOf(uint32(generalCreated)),
						Threads: types.EnvelopeMapWithRW[int, *threadInfo](map[int]*threadInfo{
							execEvent.HostProcessID: {},
						}),
					},
				}),
			},
			expectedProcess: &processNode{
				InHostIDs: ProcessIDs{
					Pid:  execEvent.HostProcessID,
					Ppid: execEvent.HostParentProcessID,
				},
				InContainerIDs: ProcessIDs{
					Pid:  execEvent.ProcessID,
					Ppid: execEvent.ParentProcessID,
				},
				ContainerID: TestContainerID,
				Cmd:         execCmd,
				ExecutionBinary: BinaryInfo{
					Path:  execBinaryPath,
					Ctime: uint(execBinaryCtime),
					Hash:  execBinaryHash,
				},
				Status:      *roaring.BitmapOf(uint32(generalCreated), uint32(executed)),
				ProcessName: execEvent.ProcessName,
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			require.NoError(t, testCase.initialTree.processExecEvent(&execEvent))
			execProcess, err := testCase.initialTree.getProcess(execEvent.HostThreadID)
			require.NoError(t, err)
			assert.ElementsMatch(t, testCase.expectedProcess.Cmd, execProcess.Cmd)
			assert.Equal(t, testCase.expectedProcess.ProcessName, execProcess.ProcessName)
			assert.Equal(t, testCase.expectedProcess.ContainerID, execProcess.ContainerID)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Pid, execProcess.InHostIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InHostIDs.Ppid, execProcess.InHostIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Pid, execProcess.InContainerIDs.Pid)
			assert.Equal(t, testCase.expectedProcess.InContainerIDs.Ppid, execProcess.InContainerIDs.Ppid)
			assert.Equal(t, testCase.expectedProcess.StartTime, execProcess.StartTime)
			assert.Equal(t, testCase.expectedProcess.Status, execProcess.Status)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Path, execProcess.ExecutionBinary.Path)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Ctime, execProcess.ExecutionBinary.Ctime)
			assert.Equal(t, testCase.expectedProcess.ExecutionBinary.Hash, execProcess.ExecutionBinary.Hash)
		})
	}
}
