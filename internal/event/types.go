package event

const (
	TypeExec   = 1
	TypeOpen   = 2
	TypeNet    = 3
	TypeSignal = 4
	TypeOom    = 5
)

type EventHeader struct {
	Type uint32
}
