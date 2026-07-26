package event

import "bytes"

type SignalEvent struct {
	Type uint32
	Pid  uint32
	Tpid uint32
	Sig  int32
	Comm [16]byte
}

func (e *SignalEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}
