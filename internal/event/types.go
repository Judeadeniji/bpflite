package event

const (
	TypeExec   = 1
	TypeOpen   = 2
	TypeNet    = 3
	TypeSignal = 4
	TypeOom    = 5
	TypeUnlink = 6
	TypeMount  = 7
	TypeSetuid = 8
	TypeBpf    = 9
	TypeModule = 10
)

type EventHeader struct {
	Type uint32
}
