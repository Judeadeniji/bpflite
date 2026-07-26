package event

import (
	"fmt"
	"strings"
	"time"
)

type SetuidEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Uid       uint32 `json:"uid"`
	Details   string `json:"details"`
}

func NewSetuidEvent(pid uint32, comm string, uid uint32) *SetuidEvent {
	comm = strings.TrimRight(comm, "\x00")

	return &SetuidEvent{
		Type:      "setuid",
		Timestamp: time.Now().Format(time.RFC3339),
		Pid:       pid,
		Comm:      comm,
		Uid:       uid,
		Details:   fmt.Sprintf("setuid to uid %d", uid),
	}
}
