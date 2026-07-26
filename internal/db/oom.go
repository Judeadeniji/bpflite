package db

import "bpflite/internal/event"

func (d *DB) InsertOom(e *event.OomEvent) error {
	_, err := d.db.Exec(
		"INSERT INTO oom_events (trigger_pid, victim_pid, trigger_comm, victim_comm, pages) VALUES (?, ?, ?, ?, ?)",
		e.TriggerPid, e.VictimPid, e.TriggerCommString(), e.VictimCommString(), e.Pages,
	)
	return err
}
