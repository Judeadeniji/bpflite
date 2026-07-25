package ui

import (
	"encoding/json"
	"fmt"
	"os"

	"bpflite/internal/event"
)

type JSONOutput struct {
	Type     string   `json:"type"`
	Pid      uint32   `json:"pid"`
	Ppid     uint32   `json:"ppid,omitempty"`
	Uid      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm"`
	Args     []string `json:"args,omitempty"`
	Filename string   `json:"filename,omitempty"`
}

func PrintJSON(e interface{}) {
	var out JSONOutput

	switch ev := e.(type) {
	case *event.ExecEvent:
		out = JSONOutput{
			Type: "execve",
			Pid:  ev.Pid,
			Ppid: ev.Ppid,
			Uid:  ev.Uid,
			Comm: ev.CommString(),
			Args: ev.ArgvList(),
		}
	case *event.OpenEvent:
		out = JSONOutput{
			Type:     "openat",
			Pid:      ev.Pid,
			Comm:     ev.CommString(),
			Filename: ev.FilenameString(),
		}
	default:
		return
	}

	b, err := json.Marshal(out)
	if err == nil {
		fmt.Fprintln(os.Stdout, string(b))
	}
}
