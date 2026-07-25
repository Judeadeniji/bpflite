package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"bpflite/internal/event"
)

type DB struct {
	db *sql.DB
}

func New(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{db: db}
	if err := d.initSchema(); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return d, nil
}

func (d *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS exec_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		pid INTEGER,
		ppid INTEGER,
		uid INTEGER,
		comm TEXT,
		args TEXT
	);

	CREATE TABLE IF NOT EXISTS open_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		pid INTEGER,
		comm TEXT,
		filename TEXT
	);

	CREATE TABLE IF NOT EXISTS net_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		pid INTEGER,
		comm TEXT,
		saddr TEXT,
		sport INTEGER,
		daddr TEXT,
		dport INTEGER,
		old_state TEXT,
		new_state TEXT
	);
	`
	_, err := d.db.Exec(schema)
	return err
}

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

func (d *DB) InsertOpen(e *event.OpenEvent) error {
	_, err := d.db.Exec(
		"INSERT INTO open_events (pid, comm, filename) VALUES (?, ?, ?)",
		e.Pid, e.CommString(), e.FilenameString(),
	)
	return err
}

func (d *DB) InsertNet(e *event.NetEvent) error {
	saddr := fmt.Sprintf("%d.%d.%d.%d", e.Saddr[0], e.Saddr[1], e.Saddr[2], e.Saddr[3])
	daddr := fmt.Sprintf("%d.%d.%d.%d", e.Daddr[0], e.Daddr[1], e.Daddr[2], e.Daddr[3])

	_, err := d.db.Exec(
		"INSERT INTO net_events (pid, comm, saddr, sport, daddr, dport, old_state, new_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		e.Pid, e.CommString(), saddr, e.Sport, daddr, e.Dport, e.OldStateString(), e.NewStateString(),
	)
	return err
}

func (d *DB) Close() error {
	return d.db.Close()
}
