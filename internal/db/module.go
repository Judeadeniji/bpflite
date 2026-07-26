package db

import (
	"bpflite/internal/event"
)

func (d *DB) InsertModule(e *event.ModuleEvent) error {
	query := `INSERT INTO module_events (timestamp, pid, comm, name) VALUES (?, ?, ?, ?)`
	_, err := d.db.Exec(query, e.Timestamp, e.Pid, e.Comm, e.Name)
	return err
}
