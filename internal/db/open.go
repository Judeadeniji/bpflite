package db

import "bpflite/internal/event"

func (d *DB) InsertOpen(e *event.OpenEvent) error {
	_, err := d.db.Exec(
		"INSERT INTO open_events (pid, comm, filename) VALUES (?, ?, ?)",
		e.Pid, e.CommString(), e.FilenameString(),
	)
	return err
}
