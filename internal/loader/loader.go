package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"bpflite/bpf"
	"bpflite/internal/event"
)

type Loader struct {
	objs   bpf.ProbeObjects
	links  []link.Link
	reader *ringbuf.Reader
}

func New(traceExec, traceOpen, traceNet, traceSignal, traceOom, traceUnlink, traceMount, traceSetuid, traceBpf, traceModule bool, filterPID uint32) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs bpf.ProbeObjects
	if err := bpf.LoadProbeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	if filterPID != 0 {
		key := uint32(0)
		if err := objs.TargetPidMap.Update(&key, &filterPID, 0); err != nil {
			objs.Close()
			return nil, fmt.Errorf("update pid filter: %w", err)
		}
	}

	var links []link.Link

	if traceExec {
		tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceSysExecve, nil)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("attach execve tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceOpen {
		tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysOpenat, nil)
		if err != nil {
			for _, ln := range links {
				ln.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach openat tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceNet {
		tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
		if err != nil {
			for _, ln := range links {
				ln.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach inet_sock_set_state tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceSignal {
		tp, err := link.Tracepoint("syscalls", "sys_enter_kill", objs.TraceSysKill, nil)
		if err != nil {
			for _, ln := range links {
				ln.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_kill tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceOom {
		tp, err := link.Tracepoint("oom", "mark_victim", objs.TraceOomMarkVictim, nil)
		if err != nil {
			for _, ln := range links {
				ln.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach oom/mark_victim tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceUnlink {
		tp, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceSysUnlinkat, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_unlinkat tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceMount {
		tp, err := link.Tracepoint("syscalls", "sys_enter_mount", objs.TraceSysMount, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_mount tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceSetuid {
		tp, err := link.Tracepoint("syscalls", "sys_enter_setuid", objs.TraceSysSetuid, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_setuid tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceBpf {
		tp, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceSysBpf, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_bpf tracepoint: %w", err)
		}
		links = append(links, tp)
	}

	if traceModule {
		tp1, err := link.Tracepoint("syscalls", "sys_enter_finit_module", objs.TraceSysFinitModule, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_finit_module tracepoint: %w", err)
		}
		links = append(links, tp1)

		tp2, err := link.Tracepoint("syscalls", "sys_enter_init_module", objs.TraceSysInitModule, nil)
		if err != nil {
			for _, ln := range links { ln.Close() }
			objs.Close()
			return nil, fmt.Errorf("attach sys_enter_init_module tracepoint: %w", err)
		}
		links = append(links, tp2)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, ln := range links {
			ln.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	return &Loader{
		objs:   objs,
		links:  links,
		reader: rd,
	}, nil
}

func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, ln := range l.links {
		if err := ln.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := l.objs.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func (l *Loader) ReadEvent() (interface{}, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("read ringbuf: %w", err)
	}

	var header event.EventHeader
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("decode event header: %w", err)
	}

	switch header.Type {
	case event.TypeExec:
		var e event.ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return nil, fmt.Errorf("decode exec event: %w", err)
		}
		return &e, nil
	case event.TypeOpen:
		var e event.OpenEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return nil, fmt.Errorf("decode open event: %w", err)
		}
		return &e, nil
	case event.TypeNet:
		var e event.NetEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return nil, fmt.Errorf("decode net event: %w", err)
		}
		return &e, nil
	case event.TypeSignal:
		var e event.SignalEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return nil, fmt.Errorf("decode signal event: %w", err)
		}
		return &e, nil
	case event.TypeOom:
		var e event.OomEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return nil, fmt.Errorf("decode oom event: %w", err)
		}
		return &e, nil
	case event.TypeUnlink:
		var raw struct {
			Type     uint32
			Pid      uint32
			Comm     [16]byte
			Pathname [256]byte
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return nil, fmt.Errorf("decode unlink event: %w", err)
		}
		return event.NewUnlinkEvent(raw.Pid, string(raw.Comm[:]), string(raw.Pathname[:])), nil
	case event.TypeMount:
		var raw struct {
			Type    uint32
			Pid     uint32
			Comm    [16]byte
			DevName [256]byte
			DirName [256]byte
			FsType  [16]byte
			Flags   uint64
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return nil, fmt.Errorf("decode mount event: %w", err)
		}
		return event.NewMountEvent(raw.Pid, string(raw.Comm[:]), string(raw.DevName[:]), string(raw.DirName[:]), string(raw.FsType[:]), raw.Flags), nil
	case event.TypeSetuid:
		var raw struct {
			Type uint32
			Pid  uint32
			Comm [16]byte
			Uid  uint32
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return nil, fmt.Errorf("decode setuid event: %w", err)
		}
		return event.NewSetuidEvent(raw.Pid, string(raw.Comm[:]), raw.Uid), nil
	case event.TypeBpf:
		var raw struct {
			Type uint32
			Pid  uint32
			Comm [16]byte
			Cmd  int32
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return nil, fmt.Errorf("decode bpf event: %w", err)
		}
		return event.NewBpfEvent(raw.Pid, string(raw.Comm[:]), raw.Cmd), nil
	case event.TypeModule:
		var raw struct {
			Type uint32
			Pid  uint32
			Comm [16]byte
			Name [64]byte
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return nil, fmt.Errorf("decode module event: %w", err)
		}
		return event.NewModuleEvent(raw.Pid, string(raw.Comm[:]), string(raw.Name[:])), nil


	default:
		return nil, fmt.Errorf("unknown event type: %d", header.Type)
	}
}
