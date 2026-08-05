package ssh

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const SSHClientVersion = "SSH-2.0-OpenSSH_9.2p1"

type KexInfo struct {
	Banner   string
	KEX      []string
	HostKeys []string
	Ciphers  []string
	MACs     []string
}

func Kex(host string, port int, timeout time.Duration) (*KexInfo, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	var banner string
	for range 50 {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line = strings.TrimRight(line, "\r\n"); strings.HasPrefix(line, "SSH-") {
			banner = line
			break
		}
	}
	if banner == "" {
		return nil, fmt.Errorf("no SSH identification string")
	}
	if _, err := conn.Write([]byte(SSHClientVersion + "\r\n")); err != nil {
		return nil, err
	}

	var lenb [4]byte
	if _, err := io.ReadFull(br, lenb[:]); err != nil {
		return nil, err
	}
	plen := binary.BigEndian.Uint32(lenb[:])
	if plen < 2 || plen > 1<<20 {
		return nil, fmt.Errorf("bad SSH packet length %d", plen)
	}
	buf := make([]byte, plen)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	padlen := int(buf[0])
	if 1+padlen > len(buf) {
		return nil, fmt.Errorf("bad padding")
	}
	payload := buf[1 : len(buf)-padlen]
	if len(payload) < 17 || payload[0] != 20 {
		return nil, fmt.Errorf("expected KEXINIT, got msg type %d", payload[0])
	}
	p := payload[17:]
	next := func() []string {
		if len(p) < 4 {
			return nil
		}
		n := int(binary.BigEndian.Uint32(p[:4]))
		p = p[4:]
		if n > len(p) {
			n = len(p)
		}
		s := string(p[:n])
		p = p[n:]
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	ki := &KexInfo{Banner: banner}
	ki.KEX = next()
	ki.HostKeys = next()
	ki.Ciphers = next()
	next()
	ki.MACs = next()
	return ki, nil
}

func (k *KexInfo) WeakAlgos() map[string][]string {
	out := map[string][]string{}
	collect := func(key string, in []string, weak func(string) bool) {
		for _, a := range in {
			if weak(strings.ToLower(strings.TrimSpace(a))) {
				out[key] = append(out[key], a)
			}
		}
	}
	collect("kex", k.KEX, func(a string) bool {
		return strings.HasSuffix(a, "-sha1") || strings.Contains(a, "group1-") ||
			strings.Contains(a, "group-exchange-sha1") || a == "diffie-hellman-group14-sha1"
	})
	collect("cipher", k.Ciphers, func(a string) bool {
		return strings.HasSuffix(a, "-cbc") || strings.HasPrefix(a, "arcfour") ||
			strings.HasPrefix(a, "3des") || strings.HasPrefix(a, "blowfish") ||
			strings.HasPrefix(a, "cast128") || a == "none"
	})
	collect("mac", k.MACs, func(a string) bool {
		return strings.HasPrefix(a, "hmac-md5") || strings.HasSuffix(a, "-96") ||
			a == "umac-64@openssh.com" || a == "hmac-sha1"
	})
	collect("hostkey", k.HostKeys, func(a string) bool {
		return a == "ssh-rsa" || a == "ssh-dss"
	})
	return out
}
