package main

import (
	"fmt"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type e2eIoUringSumitReq struct {
	cb detect.SignatureHandler
}

func (sig *e2eIoUringSumitReq) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eIoUringSumitReq) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "IO_URING_SUBMIT_REQ",
		EventName:   "IO_URING_SUBMIT_REQ",
		Version:     "0.1.0",
		Name:        "io_uring submit request Test",
		Description: "Instrumentation events E2E Tests: io_uring submit request",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eIoUringSumitReq) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "io_uring_submit_req"},
	}, nil
}

func (sig *e2eIoUringSumitReq) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "io_uring_submit_req":
		path, err := helpers.GetTraceeStringArgumentByName(eventObj, "path")
		if err != nil {
			return err
		}

		opcode, err := helpers.GetTraceeStringArgumentByName(eventObj, "opcode")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if eventObj.ProcessName != "io_uring_writev" || opcode != "IORING_OP_WRITEV" || path != "/tmp/io_uring_writev.txt" {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eIoUringSumitReq) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eIoUringSumitReq) Close() {}
