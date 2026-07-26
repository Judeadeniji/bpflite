package event

import "bytes"

type OpenEvent struct {
	Type     uint32
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func (e *OpenEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}

func (e *OpenEvent) FilenameString() string {
	idx := bytes.IndexByte(e.Filename[:], 0)
	if idx < 0 {
		return string(e.Filename[:])
	}
	return string(e.Filename[:idx])
}
