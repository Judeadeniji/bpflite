package event

import (
	"fmt"
	"strings"
	"time"
)

type MountEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	DevName   string `json:"dev_name"`
	DirName   string `json:"dir_name"`
	FsType    string `json:"fs_type"`
	Flags     uint64 `json:"flags"`
	Details   string `json:"details"`
}

func NewMountEvent(pid uint32, comm, dev, dir, fsType string, flags uint64) *MountEvent {
	comm = strings.TrimRight(comm, "\x00")
	dev = strings.TrimRight(dev, "\x00")
	dir = strings.TrimRight(dir, "\x00")
	fsType = strings.TrimRight(fsType, "\x00")

	return &MountEvent{
		Type:      "mount",
		Timestamp: time.Now().Format(time.RFC3339),
		Pid:       pid,
		Comm:      comm,
		DevName:   dev,
		DirName:   dir,
		FsType:    fsType,
		Flags:     flags,
		Details:   fmt.Sprintf("mounted %s on %s (type: %s)", dev, dir, fsType),
	}
}
