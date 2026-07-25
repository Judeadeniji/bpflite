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
	Family   uint16   `json:"family,omitempty"`
	Protocol    uint16   `json:"protocol,omitempty"`
	Sport       uint16   `json:"sport,omitempty"`
	Dport       uint16   `json:"dport,omitempty"`
	Oldstate    string   `json:"oldstate,omitempty"`
	Newstate    string   `json:"newstate,omitempty"`
	Saddr       string   `json:"saddr,omitempty"`
	Daddr       string   `json:"daddr,omitempty"`
	Description string   `json:"description,omitempty"`
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
	case *event.NetEvent:
		out = JSONOutput{
			Type:        "net",
			Pid:         ev.Pid,
			Comm:        ev.CommString(),
			Family:      ev.Family,
			Protocol:    ev.Protocol,
			Sport:       ev.Sport,
			Dport:       ev.Dport,
			Oldstate:    ev.OldStateString(),
			Newstate:    ev.NewStateString(),
			Saddr:       fmt.Sprintf("%d.%d.%d.%d", ev.Saddr[0], ev.Saddr[1], ev.Saddr[2], ev.Saddr[3]),
			Daddr:       fmt.Sprintf("%d.%d.%d.%d", ev.Daddr[0], ev.Daddr[1], ev.Daddr[2], ev.Daddr[3]),
			Description: ev.HumanDescription(),
		}
	default:
		return
	}

	b, err := json.Marshal(out)
	if err == nil {
		fmt.Fprintln(os.Stdout, string(b))
	}
}
