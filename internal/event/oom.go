package event

import "bytes"

type OomEvent struct {
	Type        uint32
	TriggerPid  uint32
	VictimPid   uint32
	TriggerComm [16]byte
	VictimComm  [16]byte
	Pages       uint64
}

func (e *OomEvent) TriggerCommString() string {
	idx := bytes.IndexByte(e.TriggerComm[:], 0)
	if idx < 0 {
		return string(e.TriggerComm[:])
	}
	return string(e.TriggerComm[:idx])
}

func (e *OomEvent) VictimCommString() string {
	idx := bytes.IndexByte(e.VictimComm[:], 0)
	if idx < 0 {
		return string(e.VictimComm[:])
	}
	return string(e.VictimComm[:idx])
}
