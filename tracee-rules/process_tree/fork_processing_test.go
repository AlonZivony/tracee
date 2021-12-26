package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const threadPID = 22482
const threadPPID = 22447
const shCtime = 1639044471927000000
const cPID = 3
const cPPID = 2

func TestProcessTree_ProcessFork(t *testing.T) {
	type expectedValues struct {
		status       types.ProcessInformationStatus
		threadsCount int
	}
	t.Run("Main thread fork", func(t *testing.T) {
		testCases := []struct {
			testName string
			tree     ProcessTree
			expected expectedValues
		}{
			{
				testName: "Existing executed process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:     shCtime,
					ContainerID:  TestContainerID,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Executed,
				}),
				expected: expectedValues{
					types.Completed,
					1,
				},
			},
			{
				testName: "Lost exit event - existing forked process",
				tree: generateProcessTree(&types.ProcessInfo{
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: 10,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: 10,
						Tid:  threadPID,
					},
					StartTime:    shCtime - 100000,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Forked,
				}),
				expected: expectedValues{
					types.Forked,
					1,
				},
			},
			{
				testName: "Lost exit event - existing completed process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sleep",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: 10,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: 10,
						Tid:  threadPID,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/busybox",
						Hash:  "",
						Ctime: shCtime - 200000,
					},
					ExecTime:     shCtime - 100000,
					StartTime:    shCtime - 100000,
					ContainerID:  "",
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Completed,
				}),
				expected: expectedValues{
					types.Forked,
					1,
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&types.ProcessInfo{
					InHostIDs: types.ProcessIDs{
						Pid: threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid: cPID,
					},
					Status: types.HollowParent,
				}),
				expected: expectedValues{
					types.Forked,
					1,
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					ContainerID:  TestContainerID,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.GeneralCreated,
				}),
				expected: expectedValues{
					types.Forked,
					1,
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes:  map[int]*types.ProcessInfo{},
					containers: map[string]*containerProcessTree{},
				},
				expected: expectedValues{
					types.Forked,
					1,
				},
			},
		}
		forkEvent := generateMainForkEvent()
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				require.NoError(t, testCase.tree.ProcessEvent(forkEvent))
				p, err := testCase.tree.GetProcessInfo(threadPID)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status, p.Status)
				assert.Equal(t, testCase.expected.threadsCount, p.ThreadsCount)
				assert.Equal(t, forkEvent.HostProcessID, p.InHostIDs.Ppid)
				assert.Equal(t, forkEvent.ProcessID, p.InContainerIDs.Ppid)
			})
		}
	})

	t.Run("Normal thread fork", func(t *testing.T) {
		testCases := []struct {
			testName string
			tree     ProcessTree
			expected expectedValues
		}{
			{
				testName: "Existing executed process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:     shCtime,
					ContainerID:  TestContainerID,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Executed,
				}),
				expected: expectedValues{
					types.Executed,
					2,
				},
			},
			{
				testName: "Existing forked process",
				tree: generateProcessTree(&types.ProcessInfo{
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					StartTime:    shCtime,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Forked,
				}),
				expected: expectedValues{
					types.Forked,
					2,
				},
			},
			{
				testName: "Existing completed process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:     shCtime,
					StartTime:    shCtime,
					ContainerID:  TestContainerID,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.Completed,
				}),
				expected: expectedValues{
					types.Completed,
					2,
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&types.ProcessInfo{
					InHostIDs: types.ProcessIDs{
						Pid: threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid: cPID,
					},
					Status: types.HollowParent,
				}),
				expected: expectedValues{
					types.GeneralCreated,
					1,
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&types.ProcessInfo{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  threadPID,
						Ppid: threadPPID,
						Tid:  threadPID,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cPID,
						Ppid: cPPID,
						Tid:  cPID,
					},
					ContainerID:  TestContainerID,
					ThreadsCount: 1,
					IsAlive:      true,
					Status:       types.GeneralCreated,
				}),
				expected: expectedValues{
					types.GeneralCreated,
					2,
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes:  map[int]*types.ProcessInfo{},
					containers: map[string]*containerProcessTree{},
				},
				expected: expectedValues{
					types.GeneralCreated,
					1,
				},
			},
		}
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				forkEvent := generateThreadForkEvent()
				require.NoError(t, testCase.tree.ProcessEvent(forkEvent))
				p, err := testCase.tree.GetProcessInfo(threadPID)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status, p.Status)
				assert.Equal(t, testCase.expected.threadsCount, p.ThreadsCount)
				assert.Equal(t, forkEvent.ProcessName, p.ProcessName)
				assert.Equal(t, forkEvent.HostProcessID, p.InHostIDs.Pid)
				assert.Equal(t, forkEvent.HostParentProcessID, p.InHostIDs.Ppid)
				assert.Equal(t, forkEvent.ProcessID, p.InContainerIDs.Pid)
				assert.Equal(t, forkEvent.ParentProcessID, p.InContainerIDs.Ppid)
			})
		}
	})

}

func generateProcessTree(p *types.ProcessInfo) ProcessTree {
	return ProcessTree{
		processes: map[int]*types.ProcessInfo{
			p.InHostIDs.Pid: p,
		},
		containers: map[string]*containerProcessTree{
			p.ContainerID: {
				Root: p,
			},
		},
	}
}

func generateMainForkEvent() external.Event {
	return external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           cPPID,
		ThreadID:            cPPID,
		ParentProcessID:     1,
		HostProcessID:       threadPPID,
		HostThreadID:        threadPPID,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(threadPPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cPPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(threadPPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cPPID)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(threadPID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(cPID)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(threadPID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cPID)},
		},
	}
}

func generateThreadForkEvent() external.Event {
	newTID := threadPID + 1
	newCTID := cPID + 1
	return external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           cPID,
		ThreadID:            cPID,
		ParentProcessID:     cPPID,
		HostProcessID:       threadPID,
		HostThreadID:        threadPID,
		HostParentProcessID: threadPPID,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(threadPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(threadPID)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cPID)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(newTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(newCTID)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(threadPID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cPID)},
		},
	}
}
