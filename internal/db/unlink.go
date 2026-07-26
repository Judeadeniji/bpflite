package db

import (
	"bpflite/internal/event"
)

func (d *DB) InsertUnlink(e *event.UnlinkEvent) error {
	query := `INSERT INTO unlink_events (timestamp, pid, comm, pathname) VALUES (?, ?, ?, ?)`
	_, err := d.db.Exec(query, e.Timestamp, e.Pid, e.Comm, e.Pathname)
	return err
}
