package main

import (
	"testing"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorePatternModification(t *testing.T) {
	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]detect.Finding
	}{
		{
			Name: "should trigger detection",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/core_pattern"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_WRONLY"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{
				"TRC-28": {
					Data: nil,
					Event: trace.Event{
						EventName: "security_file_open",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "pathname",
								},
								Value: interface{}("/proc/sys/kernel/core_pattern"),
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "flags",
								},
								Value: interface{}("O_WRONLY"),
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-28",
						Version:     "1",
						Name:        "Core dumps configuration file modification detected",
						Description: "Modification of the core dump configuration file (core_pattern) detected. Core dumps are usually written to disk when a program crashes. Certain modifications enable container escaping through the kernel core_pattern feature.",
						Properties: map[string]interface{}{
							"Severity":             3,
							"Category":             "privilege-escalation",
							"Technique":            "Escape to Host",
							"Kubernetes_Technique": "",
							"id":                   "attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665",
							"external_id":          "T1611",
						},
					},
				},
			},
		},
		{
			Name: "should not trigger detection - wrong open flags",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/proc/sys/kernel/core_pattern"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_RDONLY"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{},
		},
		{
			Name: "should not trigger detection - wrong path",
			Events: []trace.Event{
				{
					EventName: "security_file_open",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: interface{}("/sys/kernel/something"),
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "flags",
							},
							Value: interface{}("O_WRONLY"),
						},
					},
				},
			},
			Findings: map[string]detect.Finding{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			holder := signaturestest.FindingsHolder{}
			sig := CorePatternModification{}
			sig.Init(holder.OnFinding)

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}