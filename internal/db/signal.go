package db

import "bpflite/internal/event"

func (d *DB) InsertSignal(e *event.SignalEvent) error {
	_, err := d.db.Exec(
		"INSERT INTO signal_events (pid, tpid, sig, comm) VALUES (?, ?, ?, ?)",
		e.Pid, e.Tpid, e.Sig, e.CommString(),
	)
	return err
}
