package db

import (
	"bpflite/internal/event"
)

func (d *DB) InsertMount(e *event.MountEvent) error {
	query := `INSERT INTO mount_events (timestamp, pid, comm, dev_name, dir_name, fs_type, flags) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := d.db.Exec(query, e.Timestamp, e.Pid, e.Comm, e.DevName, e.DirName, e.FsType, e.Flags)
	return err
}
