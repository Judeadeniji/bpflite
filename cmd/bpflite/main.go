package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"bpflite/internal/db"
	"bpflite/internal/event"
	"bpflite/internal/loader"
	"bpflite/internal/ui"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	daemonize  bool
	pidFilter  uint32
	version    = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "bpflite",
		Short:   "bpflite is a lightweight eBPF tracer",
		Version: version,
	}

	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace kernel events",
	}

	execCmd := &cobra.Command{
		Use:   "exec",
		Short: "Trace execve syscalls",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTracer(true, false, false, 0)
		},
	}

	openCmd := &cobra.Command{
		Use:   "open",
		Short: "Trace openat syscalls",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTracer(false, true, false, pidFilter)
		},
	}

	netCmd := &cobra.Command{
		Use:   "net",
		Short: "Trace TCP connection lifecycle",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTracer(false, false, true, pidFilter)
		},
	}

	openCmd.Flags().Uint32Var(&pidFilter, "pid", 0, "Filter events by PID")
	netCmd.Flags().Uint32Var(&pidFilter, "pid", 0, "Filter events by PID")

	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	traceCmd.AddCommand(execCmd, openCmd, netCmd)

	recordCmd := &cobra.Command{
		Use:   "record",
		Short: "Record all events to SQLite database",
		RunE: func(cmd *cobra.Command, args []string) error {
			if daemonize {
				os.MkdirAll("data", 0755)
				logFile, err := os.OpenFile("data/bpflite.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err != nil {
					return err
				}
				
				execArgs := []string{"record"}
				c := exec.Command(os.Args[0], execArgs...)
				c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				c.Stdout = logFile
				c.Stderr = logFile
				
				if err := c.Start(); err != nil {
					return err
				}
				
				fmt.Printf("bpflite daemon started in background (PID %d)\n", c.Process.Pid)
				fmt.Println("Logs: data/bpflite.log")
				fmt.Println("DB: data/bpflite.sqlite")
				fmt.Println("Run 'bpflite stop' to stop it.")
				os.Exit(0)
			}
			return runDaemon()
		},
	}
	recordCmd.Flags().BoolVarP(&daemonize, "daemon", "d", false, "Run in the background as a daemon")

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the background bpflite daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := os.ReadFile("data/bpflite.pid")
			if err != nil {
				return fmt.Errorf("daemon is not running (could not read data/bpflite.pid)")
			}
			pidStr := strings.TrimSpace(string(b))
			var pid int
			fmt.Sscanf(pidStr, "%d", &pid)
			
			process, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			if err := process.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("failed to stop daemon: %w", err)
			}
			
			fmt.Println("Daemon stopped.")
			os.Remove("data/bpflite.pid")
			return nil
		},
	}

	historyCmd := &cobra.Command{
		Use:   "history",
		Short: "Query historical events from SQLite database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHistory()
		},
	}

	rootCmd.AddCommand(traceCmd, recordCmd, stopCmd, historyCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon() error {
	os.MkdirAll("data", 0755)
	
	pidFile := "data/bpflite.pid"
	os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	defer os.Remove(pidFile)

	l, err := loader.New(true, true, true, 0)
	if err != nil {
		return fmt.Errorf("failed to initialize loader: %w", err)
	}
	defer l.Close()

	database, err := db.New("data/bpflite.sqlite")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	fmt.Println("bpflite daemon running. Recording events to data/bpflite.sqlite...")

	events := make(chan interface{}, 1000)
	go func() {
		for {
			e, err := l.ReadEvent()
			if err != nil {
				if err.Error() == "ring buffer closed" {
					return
				}
				fmt.Printf("Error reading event: %v\n", err)
				continue
			}
			events <- e
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-sig:
			fmt.Println("\nShutting down daemon...")
			return nil
		case e := <-events:
			switch ev := e.(type) {
			case *event.ExecEvent:
				database.InsertExec(ev)
			case *event.OpenEvent:
				database.InsertOpen(ev)
			case *event.NetEvent:
				database.InsertNet(ev)
			}
		}
	}
}

func runHistory() error {
	fmt.Println("History feature coming soon (query data/bpflite.sqlite using standard sqlite3 tools for now).")
	return nil
}

func runTracer(traceExec, traceOpen, traceNet bool, filterPID uint32) error {
	l, err := loader.New(traceExec, traceOpen, traceNet, filterPID)
	if err != nil {
		return fmt.Errorf("failed to initialize loader: %w", err)
	}
	defer l.Close()

	if jsonOutput {
		runJSON(l)
	} else {
		runTUI(l)
	}
	return nil
}

func runJSON(l *loader.Loader) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		l.Close()
		os.Exit(0)
	}()

	for {
		e, err := l.ReadEvent()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		ui.PrintJSON(e)
	}
}

func runTUI(l *loader.Loader) {
	p := tea.NewProgram(ui.NewUIModel(), tea.WithAltScreen())

	go func() {
		for {
			e, err := l.ReadEvent()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					break
				}
				continue
			}
			p.Send(e)
		}
	}()

	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
