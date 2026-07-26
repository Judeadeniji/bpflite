package db

import (
	"strings"

	"bpflite/internal/event"
)

func (d *DB) InsertExec(e *event.ExecEvent) error {
	args := []string{}
	for _, arg := range e.Argv {
		idx := strings.IndexByte(string(arg[:]), 0)
		if idx <= 0 {
			continue
		}
		args = append(args, string(arg[:idx]))
	}

	_, err := d.db.Exec(
		"INSERT INTO exec_events (pid, ppid, uid, comm, args) VALUES (?, ?, ?, ?, ?)",
		e.Pid, e.Ppid, e.Uid, e.CommString(), strings.Join(args, " "),
	)
	return err
}
