package db

import (
	"bpflite/internal/event"
)

func (d *DB) InsertSetuid(e *event.SetuidEvent) error {
	query := `INSERT INTO setuid_events (timestamp, pid, comm, uid) VALUES (?, ?, ?, ?)`
	_, err := d.db.Exec(query, e.Timestamp, e.Pid, e.Comm, e.Uid)
	return err
}
