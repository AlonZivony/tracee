package proctree

import (
	"testing"

	"github.com/RoaringBitmap/roaring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/types/trace"
)

const pid = 22482
const ppid = 22447
const shCtime = 1639044471927000000
const forkTime = 1639044471927303690
const cpid = 3
const cppid = 2
const threadTID = pid + 1
const threadCTID = cpid + 1

func TestProcessTree_ProcessFork(t *testing.T) {
	type expectedValues struct {
		status        roaring.Bitmap
		livingThreads map[int]timestamp
	}
	t.Run("Main thread fork", func(t *testing.T) {
		testCases := []struct {
			testName string
			tree     ProcessTree
			expected expectedValues
		}{
			{
				testName: "Existing executed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					ContainerID: TestContainerID,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(executed), uint32(generalCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
			{
				testName: "Lost exit event - existing forked process",
				tree: generateProcessTree(&processNode{
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					InContainerIDs: ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					StartTime: shCtime - 100000,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(forked)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(forked), uint32(generalCreated)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
			{
				testName: "Lost exit event - existing completed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sleep",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					InContainerIDs: ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					ExecutionBinary: BinaryInfo{
						Path:  "/bin/busybox",
						Hash:  "",
						Ctime: shCtime - 200000,
					},
					ExecTime:    shCtime - 100000,
					StartTime:   shCtime - 100000,
					ContainerID: "",
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(forked), uint32(generalCreated)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&processNode{
					InHostIDs: ProcessIDs{
						Pid: pid,
					},
					InContainerIDs: ProcessIDs{
						Pid: cpid,
					},
					Status: *roaring.BitmapOf(uint32(hollowParent)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(forked)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ContainerID: TestContainerID,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(forked)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes: map[int]*processNode{},
				},
				expected: expectedValues{
					*roaring.BitmapOf(uint32(forked), uint32(generalCreated)),
					map[int]timestamp{
						pid: forkTime,
					},
				},
			},
		}
		forkEvent := generateMainForkEvent()
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				require.NoError(t, testCase.tree.processForkEvent(&forkEvent))
				p, err := testCase.tree.getProcess(pid)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status.ToArray(), p.Status.ToArray())
				assert.Equal(t, len(testCase.expected.livingThreads), len(p.Threads))
				for livingTID, info := range testCase.expected.livingThreads {
					assert.Contains(t, p.Threads, livingTID)
					assert.Equal(t, info, p.Threads[livingTID].forkTime)
				}
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
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					ContainerID: TestContainerID,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated), uint32(executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(executed)),
					map[int]timestamp{
						pid:       shCtime,
						threadTID: forkTime,
					},
				},
			},
			{
				testName: "Existing forked process",
				tree: generateProcessTree(&processNode{
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					StartTime:   shCtime,
					ProcessName: "sh",
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated), uint32(forked)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(forked)),
					map[int]timestamp{
						pid:       shCtime,
						threadTID: forkTime,
					},
				},
			},
			{
				testName: "Existing completed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					StartTime:   shCtime,
					ContainerID: TestContainerID,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated), uint32(forked), uint32(executed)),
					map[int]timestamp{
						pid:       shCtime,
						threadTID: forkTime,
					},
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&processNode{
					InHostIDs: ProcessIDs{
						Pid: pid,
					},
					InContainerIDs: ProcessIDs{
						Pid: cpid,
					},
					Status:  *roaring.BitmapOf(uint32(hollowParent)),
					Threads: map[int]*threadInfo{},
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated)),
					map[int]timestamp{
						pid:       0,
						threadTID: forkTime,
					},
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ContainerID: TestContainerID,
					Threads: map[int]*threadInfo{
						pid: {forkTime: shCtime},
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(generalCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated)),
					map[int]timestamp{
						pid:       shCtime,
						threadTID: forkTime,
					},
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes: map[int]*processNode{},
				},
				expected: expectedValues{
					*roaring.BitmapOf(uint32(generalCreated)),
					map[int]timestamp{
						pid:       0,
						threadTID: forkTime,
					},
				},
			},
		}
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				forkEvent := generateThreadForkEvent()
				require.NoError(t, testCase.tree.processForkEvent(&forkEvent))
				p, err := testCase.tree.getProcess(pid)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status.ToArray(), p.Status.ToArray())
				assert.Equal(t, len(testCase.expected.livingThreads), len(p.Threads))
				for livingTID, info := range testCase.expected.livingThreads {
					assert.Contains(t, p.Threads, livingTID)
					assert.Equal(t, info, p.Threads[livingTID].forkTime)
				}
				assert.Equal(t, forkEvent.ProcessName, p.ProcessName)
				assert.Equal(t, forkEvent.HostProcessID, p.InHostIDs.Pid)
				assert.Equal(t, forkEvent.HostParentProcessID, p.InHostIDs.Ppid)
				assert.Equal(t, forkEvent.ProcessID, p.InContainerIDs.Pid)
				assert.Equal(t, forkEvent.ParentProcessID, p.InContainerIDs.Ppid)
			})
		}
	})
}

func generateProcessTree(p *processNode) ProcessTree {
	return ProcessTree{
		processes: map[int]*processNode{
			p.InHostIDs.Pid: p,
		},
	}
}

func generateMainForkEvent() trace.Event {
	return trace.Event{
		Timestamp:           forkTime,
		ProcessID:           cppid,
		ThreadID:            cppid,
		ParentProcessID:     1,
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
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cppid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cpid)},
		},
	}
}

func generateThreadForkEvent() trace.Event {
	return trace.Event{
		Timestamp:           forkTime,
		ProcessID:           cpid,
		ThreadID:            cpid,
		ParentProcessID:     cppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
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
			{ArgMeta: trace.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: trace.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(threadTID)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(threadCTID)},
			{ArgMeta: trace.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: trace.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cpid)},
		},
	}
}
