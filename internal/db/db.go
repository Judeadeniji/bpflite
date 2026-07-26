package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
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

	CREATE TABLE IF NOT EXISTS signal_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		pid INTEGER,
		tpid INTEGER,
		sig INTEGER,
		comm TEXT
	);

	CREATE TABLE IF NOT EXISTS oom_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		trigger_pid INTEGER,
		victim_pid INTEGER,
		trigger_comm TEXT,
		victim_comm TEXT,
		pages INTEGER
	);
	`
	_, err := d.db.Exec(schema)
	return err
}

func (d *DB) Close() error {
	return d.db.Close()
}

type HistoryEvent struct {
	Type      string
	Timestamp string
	Pid       int
	Comm      string
	Details   string
}

func (d *DB) QueryHistory(limit int) ([]HistoryEvent, error) {
	query := `
	SELECT 'exec' as type, timestamp, pid, comm, args as details FROM exec_events
	UNION ALL
	SELECT 'open' as type, timestamp, pid, comm, filename as details FROM open_events
	UNION ALL
	SELECT 'net' as type, timestamp, pid, comm, saddr || ':' || sport || ' -> ' || daddr || ':' || dport || ' (' || old_state || ' -> ' || new_state || ')' as details FROM net_events
	UNION ALL
	SELECT 'signal' as type, timestamp, pid, comm, 'sent SIG ' || sig || ' to PID ' || tpid as details FROM signal_events
	UNION ALL
	SELECT 'oom' as type, timestamp, trigger_pid as pid, trigger_comm as comm, 'killed ' || victim_comm || ' (PID ' || victim_pid || ') reclaiming ' || pages || ' pages' as details FROM oom_events
	ORDER BY timestamp DESC
	LIMIT ?
	`
	rows, err := d.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []HistoryEvent
	for rows.Next() {
		var e HistoryEvent
		if err := rows.Scan(&e.Type, &e.Timestamp, &e.Pid, &e.Comm, &e.Details); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
