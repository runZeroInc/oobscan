package ssdp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	From     string
	Location string
	Server   string
	USN      string
	ST       string
	Headers  map[string]string
	Raw      string
	Vendor   string
}

func MSearch(st string, timeout time.Duration) ([]Result, error) {
	if st == "" {
		st = "upnp:rootdevice"
	}
	laddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + st + "\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(req), raddr); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	var out []Result
	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		r := parseReply(buf[:n])
		r.From = src.String()
		r.Vendor = guessVendor(r)
		out = append(out, r)
	}
	return out, nil
}

func UnicastSearch(host string, st string, timeout time.Duration) (*Result, error) {
	if st == "" {
		st = "upnp:rootdevice"
	}
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:1900", host), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " + st + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	r := parseReply(buf[:n])
	r.From = host
	r.Vendor = guessVendor(r)
	return &r, nil
}

func parseReply(pkt []byte) Result {
	r := Result{Headers: map[string]string{}, Raw: string(pkt)}
	sc := bufio.NewScanner(strings.NewReader(string(pkt)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ":"); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			r.Headers[k] = v
			switch k {
			case "location":
				r.Location = v
			case "server":
				r.Server = v
			case "usn":
				r.USN = v
			case "st":
				r.ST = v
			}
		}
	}
	return r
}

func guessVendor(r Result) string {
	blob := strings.ToLower(r.Server + " " + r.USN + " " + r.Location)
	switch {
	case strings.Contains(blob, "ilo"):
		return "hpe"
	case strings.Contains(blob, "idrac"):
		return "dell"
	case strings.Contains(blob, "aten") || strings.Contains(blob, "supermicro"):
		return "supermicro"
	case strings.Contains(blob, "megarac") || strings.Contains(blob, "ami"):
		return "ami"
	case strings.Contains(blob, "avocent"):
		return "avocent"
	case strings.Contains(blob, "raritan"):
		return "raritan"
	case strings.Contains(blob, "xclarity"):
		return "lenovo"
	}
	return ""
}
