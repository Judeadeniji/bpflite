package db

import (
	"fmt"

	"bpflite/internal/event"
)

func (d *DB) InsertNet(e *event.NetEvent) error {
	saddr := fmt.Sprintf("%d.%d.%d.%d", e.Saddr[0], e.Saddr[1], e.Saddr[2], e.Saddr[3])
	daddr := fmt.Sprintf("%d.%d.%d.%d", e.Daddr[0], e.Daddr[1], e.Daddr[2], e.Daddr[3])

	_, err := d.db.Exec(
		"INSERT INTO net_events (pid, comm, saddr, sport, daddr, dport, old_state, new_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		e.Pid, e.CommString(), saddr, e.Sport, daddr, e.Dport, e.OldStateString(), e.NewStateString(),
	)
	return err
}
