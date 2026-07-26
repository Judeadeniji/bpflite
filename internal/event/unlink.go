package event

import (
	"fmt"
	"strings"
	"time"
)

type UnlinkEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Pathname  string `json:"pathname"`
	Details   string `json:"details"`
}

func NewUnlinkEvent(pid uint32, comm string, pathname string) *UnlinkEvent {
	comm = strings.TrimRight(comm, "\x00")
	pathname = strings.TrimRight(pathname, "\x00")

	return &UnlinkEvent{
		Type:      "unlink",
		Timestamp: time.Now().Format(time.RFC3339),
		Pid:       pid,
		Comm:      comm,
		Pathname:  pathname,
		Details:   fmt.Sprintf("deleted file: %s", pathname),
	}
}
