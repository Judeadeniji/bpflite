package event

import "bytes"

type ExecEvent struct {
	Type uint32
	Pid  uint32
	Ppid uint32
	Uid  uint32
	Comm [16]byte
	Argv [16][64]byte
}

func (e *ExecEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}

func (e *ExecEvent) ArgvList() []string {
	var args []string
	for i := 0; i < len(e.Argv); i++ {
		if e.Argv[i][0] == 0 {
			break
		}
		idx := bytes.IndexByte(e.Argv[i][:], 0)
		if idx < 0 {
			args = append(args, string(e.Argv[i][:]))
		} else {
			args = append(args, string(e.Argv[i][:idx]))
		}
	}
	return args
}
