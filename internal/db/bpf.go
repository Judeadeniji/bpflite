package db

import (
	"bpflite/internal/event"
)

func (d *DB) InsertBpf(e *event.BpfEvent) error {
	query := `INSERT INTO bpf_events (timestamp, pid, comm, cmd) VALUES (?, ?, ?, ?)`
	_, err := d.db.Exec(query, e.Timestamp, e.Pid, e.Comm, e.Cmd)
	return err
}
