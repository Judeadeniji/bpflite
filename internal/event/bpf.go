package event

import (
	"fmt"
	"strings"
	"time"
)

type BpfEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Cmd       int32  `json:"cmd"`
	Details   string `json:"details"`
}

func NewBpfEvent(pid uint32, comm string, cmd int32) *BpfEvent {
	comm = strings.TrimRight(comm, "\x00")

	cmdNames := map[int32]string{
		0: "BPF_MAP_CREATE",
		1: "BPF_MAP_LOOKUP_ELEM",
		2: "BPF_MAP_UPDATE_ELEM",
		3: "BPF_MAP_DELETE_ELEM",
		4: "BPF_MAP_GET_NEXT_KEY",
		5: "BPF_PROG_LOAD",
		6: "BPF_OBJ_PIN",
		7: "BPF_OBJ_GET",
	}

	cmdStr := cmdNames[cmd]
	if cmdStr == "" {
		cmdStr = fmt.Sprintf("UNKNOWN(%d)", cmd)
	}

	return &BpfEvent{
		Type:      "bpf",
		Timestamp: time.Now().Format(time.RFC3339),
		Pid:       pid,
		Comm:      comm,
		Cmd:       cmd,
		Details:   fmt.Sprintf("bpf syscall: %s", cmdStr),
	}
}
