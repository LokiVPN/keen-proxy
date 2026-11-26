package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	tcpStreams  = 16
	tcpBytes    = 4096
	udpBytes    = 1024
	dnsBatch    = 64
	echoTimeout = 2 * time.Second
)

type tunnelEvidence struct {
	Target     string `json:"target"`
	TCPStreams int    `json:"tcp_streams"`
	TCPEchoes  int    `json:"tcp_echoes"`
	TCPBytes   int    `json:"tcp_bytes"`
	UDPEchoes  int    `json:"udp_echoes"`
	UDPBytes   int    `json:"udp_bytes"`
}

type tunnel struct {
	tcp      []net.Conn
	udp      net.Conn
	evidence tunnelEvidence
}

func openTunnel(target string) (*tunnel, error) {
	t := &tunnel{evidence: tunnelEvidence{Target: target}}
	for range tcpStreams {
		conn, err := net.DialTimeout("tcp", target, echoTimeout)
		if err != nil {
			t.close()
			return nil, err
		}
		t.tcp = append(t.tcp, conn)
	}
	var err error
	t.udp, err = net.DialTimeout("udp", target, echoTimeout)
	if err != nil {
		t.close()
		return nil, err
	}
	t.evidence.TCPStreams = len(t.tcp)
	return t, nil
}

func (t *tunnel) close() {
	for _, conn := range t.tcp {
		conn.Close()
	}
	if t.udp != nil {
		t.udp.Close()
	}
}

// exchange sends exactly one payload on every open stream for each DNS batch.
// Count bytes only after the matching echo returns.
func (t *tunnel) exchange(round int) error {
	var payload [tcpBytes]byte
	binary.BigEndian.PutUint64(payload[:], uint64(round))
	for _, conn := range t.tcp {
		if err := echo(conn, payload[:], false); err != nil {
			return fmt.Errorf("TCP echo to %s in round %d: %w", t.evidence.Target, round, err)
		}
		t.evidence.TCPEchoes++
		t.evidence.TCPBytes += tcpBytes
	}
	if err := echo(t.udp, payload[:udpBytes], true); err != nil {
		return fmt.Errorf("UDP echo to %s in round %d: %w", t.evidence.Target, round, err)
	}
	t.evidence.UDPEchoes++
	t.evidence.UDPBytes += udpBytes
	return nil
}

func echo(conn net.Conn, payload []byte, datagram bool) error {
	if err := conn.SetDeadline(time.Now().Add(echoTimeout)); err != nil {
		return err
	}
	if n, err := conn.Write(payload); err != nil {
		return err
	} else if n != len(payload) {
		return io.ErrShortWrite
	}
	var received [tcpBytes + 1]byte
	var n int
	var err error
	if datagram {
		n, err = conn.Read(received[:len(payload)+1])
	} else {
		n, err = io.ReadFull(conn, received[:len(payload)])
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(received[:n], payload) {
		return fmt.Errorf("payload mismatch (%d bytes)", n)
	}
	return nil
}
