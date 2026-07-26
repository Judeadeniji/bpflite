package event

import (
	"bytes"
	"fmt"
)

type NetEvent struct {
	Type     uint32
	Pid      uint32
	Comm     [16]byte
	Family   uint16
	Protocol uint16
	Sport    uint16
	Dport    uint16
	Oldstate int32
	Newstate int32
	Saddr    [4]byte
	Daddr    [4]byte
	SaddrV6  [16]byte
	DaddrV6  [16]byte
}

func (e *NetEvent) CommString() string {
	idx := bytes.IndexByte(e.Comm[:], 0)
	if idx < 0 {
		return string(e.Comm[:])
	}
	return string(e.Comm[:idx])
}

func tcpStateToString(state int32) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSED"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	case 12:
		return "NEW_SYN_RECV"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

func (e *NetEvent) OldStateString() string {
	return tcpStateToString(e.Oldstate)
}

func (e *NetEvent) NewStateString() string {
	return tcpStateToString(e.Newstate)
}

func (e *NetEvent) HumanDescription() string {
	daddr := fmt.Sprintf("%d.%d.%d.%d", e.Daddr[0], e.Daddr[1], e.Daddr[2], e.Daddr[3])
	
	portLabel := fmt.Sprintf("port %d", e.Dport)
	switch e.Dport {
	case 80: portLabel = "port 80 (HTTP web traffic)"
	case 443: portLabel = "port 443 (HTTPS secure web)"
	case 22: portLabel = "port 22 (SSH)"
	case 53: portLabel = "port 53 (DNS lookup)"
	case 3306: portLabel = "port 3306 (MySQL)"
	case 5432: portLabel = "port 5432 (Postgres)"
	case 6379: portLabel = "port 6379 (Redis)"
	}

	if e.Oldstate == 7 && e.Newstate == 2 { // CLOSED -> SYN_SENT
		return fmt.Sprintf("Connecting out to %s on %s", daddr, portLabel)
	} else if e.Oldstate == 2 && e.Newstate == 1 { // SYN_SENT -> ESTABLISHED
		return fmt.Sprintf("Successfully connected to %s", daddr)
	} else if e.Oldstate == 10 && e.Newstate == 3 { // LISTEN -> SYN_RECV
		return fmt.Sprintf("Receiving incoming connection from %s", daddr)
	} else if e.Oldstate == 3 && e.Newstate == 1 { // SYN_RECV -> ESTABLISHED
		return fmt.Sprintf("Accepted incoming connection from %s", daddr)
	} else if e.Oldstate == 1 && (e.Newstate == 4 || e.Newstate == 8 || e.Newstate == 7) { 
		// ESTABLISHED -> FIN_WAIT1 / CLOSE_WAIT / CLOSED
		return fmt.Sprintf("Closing connection with %s", daddr)
	} else if e.Oldstate == 10 && e.Newstate == 7 { // LISTEN -> CLOSED
		return fmt.Sprintf("Stopped listening for connections on local port %d", e.Sport)
	} else if e.Oldstate == 7 && e.Newstate == 10 { // CLOSED -> LISTEN
		return fmt.Sprintf("Started listening for incoming connections on local port %d", e.Sport)
	}
	
	return fmt.Sprintf("Network activity with %s on %s (%s -> %s)", daddr, portLabel, e.OldStateString(), e.NewStateString())
}
