package event

import (
	"fmt"
	"strings"
	"time"
)

type ModuleEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Name      string `json:"name"`
	Details   string `json:"details"`
}

func NewModuleEvent(pid uint32, comm string, name string) *ModuleEvent {
	comm = strings.TrimRight(comm, "\x00")
	name = strings.TrimRight(name, "\x00")

	if name == "" {
		name = "<unknown>"
	}

	return &ModuleEvent{
		Type:      "module",
		Timestamp: time.Now().Format(time.RFC3339),
		Pid:       pid,
		Comm:      comm,
		Name:      name,
		Details:   fmt.Sprintf("loaded kernel module: %s", name),
	}
}
