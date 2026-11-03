package asd

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// MockServer is an in-process ASD server for tests. It answers the
// agent-control queries with the same shapes the real daemon uses and returns a
// configurable IDCODE for JTAG scans. It rejects DMA/unsupported message types
// with ASD_MSG_NOT_SUPPORTED, matching the shipped firmware.
type MockServer struct {
	IDCODE   uint32
	Version  string
	ln       net.Listener
	conns    sync.Map
	wg       sync.WaitGroup
	closed   chan struct{}
	closeOne sync.Once
}

// StartMockServer starts a MockServer on 127.0.0.1 and returns it with the bound
// host and port.
func StartMockServer(idcode uint32, version string) (*MockServer, string, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", 0, err
	}
	m := &MockServer{IDCODE: idcode, Version: version, ln: ln, closed: make(chan struct{})}
	m.wg.Add(1)
	go m.serve()
	addr := ln.Addr().(*net.TCPAddr)
	return m, addr.IP.String(), addr.Port, nil
}

// Close stops the server.
func (m *MockServer) Close() {
	m.closeOne.Do(func() {
		close(m.closed)
		_ = m.ln.Close()
		m.conns.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
	})
	m.wg.Wait()
}

func (m *MockServer) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
				return
			}
		}
		m.wg.Go(func() {
			m.handle(conn)
		})
	}
}

func (m *MockServer) handle(conn net.Conn) {
	m.conns.Store(conn, struct{}{})
	defer m.conns.Delete(conn)
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{'+'}); err != nil {
		return
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		head := make([]byte, HeaderSize)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		h := UnpackHeader(head)
		var body []byte
		if h.Size > 0 {
			body = make([]byte, h.Size)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		respType, status, payload := m.respond(h, body)
		out := Header{Type: respType, Size: len(payload), CmdStat: status, Tag: h.Tag, Origin: h.Origin}
		if _, err := conn.Write(append(out.Pack(), payload...)); err != nil {
			return
		}
	}
}

func (m *MockServer) respond(h Header, body []byte) (byte, byte, []byte) {
	switch h.Type {
	case TypeAgentControl:
		return m.agent(h.CmdStat, body)
	case TypeJTAG:
		// Return the IDCODE as the TDO for any read scan.
		tdo := make([]byte, 4)
		binary.LittleEndian.PutUint32(tdo, m.IDCODE)
		return TypeJTAG, StatusSuccess, tdo
	default:
		// DMA/SPP/I2C etc. are not supported by this build.
		return h.Type, StatusMsgNotSupported, nil
	}
}

func (m *MockServer) agent(cmd byte, body []byte) (byte, byte, []byte) {
	switch cmd {
	case AgentObtainVersion:
		ver := []byte(m.Version)
		if len(ver) > 15 {
			ver = ver[:15]
		}
		for len(ver) < 15 {
			ver = append(ver, 0)
		}
		out := append([]byte{AgentObtainVersion}, ver...)
		return TypeAgentControl, StatusSuccess, out
	case AgentMaxDataSize:
		return TypeAgentControl, StatusSuccess, []byte{AgentMaxDataSize, 0xB8, 0x0B}
	case AgentNumInFlight:
		return TypeAgentControl, StatusSuccess, []byte{AgentNumInFlight, 0x14}
	case AgentSupportedJTAGChain:
		return TypeAgentControl, StatusSuccess, []byte{AgentSupportedJTAGChain, 0x01}
	case AgentLoopback:
		return TypeAgentControl, StatusSuccess, body
	default:
		return TypeAgentControl, StatusMsgNotSupported, nil
	}
}
