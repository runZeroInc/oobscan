package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

const AllNodes = "ff02::1"

const protocolICMPv6 = 58

const DefaultWait = 3 * time.Second

type Options struct {
	Wait     time.Duration
	IPMIPort int
	SkipICMP bool
	SkipIPMI bool
	Log      func(string)
}

func (o Options) wait() time.Duration {
	if o.Wait <= 0 {
		return DefaultWait
	}
	return o.Wait
}

func (o Options) ipmiPort() int {
	if o.IPMIPort <= 0 {
		return 623
	}
	return o.IPMIPort
}

func (o Options) log(format string, args ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, args...))
	}
}

type Responder struct {
	Addr netip.Addr
	Via  []string
}

func (r Responder) Host() string { return r.Addr.String() }

func IsSpec(tok string) bool {
	addr, _, ok := parseSpec(tok)
	return ok && addr.Is6() && addr.IsMulticast()
}

func parseSpec(tok string) (group netip.Addr, zone string, ok bool) {
	t := strings.TrimSpace(tok)
	t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	addr, err := netip.ParseAddr(t)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return addr.WithZone(""), addr.Zone(), true
}

func LinkLocal(ctx context.Context, spec string, opt Options) ([]Responder, error) {
	group, zone, ok := parseSpec(spec)
	if !ok || !group.Is6() || !group.IsMulticast() {
		return nil, fmt.Errorf("not an IPv6 multicast spec: %q", spec)
	}
	zones := []string{zone}
	if zone != "" {

		if err := checkZone(zone); err != nil {
			return nil, err
		}
	}
	if zone == "" {
		var err error
		if zones, err = multicastZones(); err != nil {
			return nil, err
		}
		if len(zones) == 0 {
			return nil, errors.New("no IPv6 link-local capable interfaces found")
		}
		opt.log("link-local discovery: no zone in %q, sweeping %s", spec, strings.Join(zones, ", "))
	}

	var (
		hits hitSet
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)
	for _, z := range zones {
		if !opt.SkipICMP {
			wg.Add(1)
			go func(z string) {
				defer wg.Done()
				if err := icmpSweep(ctx, group, z, opt, hits.recorder(z, "icmp6")); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("icmp6 sweep on %s: %w", z, err))
					mu.Unlock()
				}
			}(z)
		}
		if !opt.SkipIPMI {
			wg.Add(1)
			go func(z string) {
				defer wg.Done()
				if err := rmcpSweep(ctx, group, z, opt, hits.recorder(z, "rmcp")); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("rmcp sweep on %s: %w", z, err))
					mu.Unlock()
				}
			}(z)
		}
	}
	wg.Wait()

	out := hits.responders()

	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for _, err := range errs {
		opt.log("link-local discovery: %v", err)
	}
	return out, nil
}

type hitSet struct {
	mu   sync.Mutex
	hits map[netip.Addr]map[string]bool
}

func (h *hitSet) recorder(zone, via string) func(netip.Addr) {
	return func(src netip.Addr) {
		src = src.Unmap()
		if !src.IsValid() || src.Is4() || src.IsMulticast() || src.IsUnspecified() {
			return
		}

		if src.IsLinkLocalUnicast() {
			src = src.WithZone(zone)
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.hits == nil {
			h.hits = map[netip.Addr]map[string]bool{}
		}
		if h.hits[src] == nil {
			h.hits[src] = map[string]bool{}
		}
		h.hits[src][via] = true
	}
}

func (h *hitSet) responders() []Responder {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Responder, 0, len(h.hits))
	for addr, via := range h.hits {
		vias := make([]string, 0, len(via))
		for v := range via {
			vias = append(vias, v)
		}
		sort.Strings(vias)
		out = append(out, Responder{Addr: addr, Via: vias})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

func ResolveSpecs(ctx context.Context, hosts []string, opt Options) ([]string, error) {
	if len(hosts) == 0 {
		return hosts, nil
	}
	var (
		out  = make([]string, 0, len(hosts))
		seen = make(map[string]bool, len(hosts))
		errs []error
	)
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range hosts {
		if !IsSpec(h) {
			add(h)
			continue
		}
		found, err := LinkLocal(ctx, h, opt)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h, err))
			continue
		}
		opt.log("link-local discovery %s: %d host(s)", h, len(found))
		for _, r := range found {
			opt.log("  %s (%s)", r.Host(), strings.Join(r.Via, "+"))
			add(r.Host())
		}
	}
	if len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	return out, nil
}

func checkZone(zone string) error {
	ifi, err := net.InterfaceByName(zone)
	if err != nil {
		if n, cerr := strconv.Atoi(zone); cerr == nil {
			ifi, err = net.InterfaceByIndex(n)
		}
	}
	if err != nil || ifi == nil {
		names, _ := multicastZones()
		if len(names) > 0 {
			return fmt.Errorf("unknown interface %q (candidates: %s)", zone, strings.Join(names, ", "))
		}
		return fmt.Errorf("unknown interface %q", zone)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is down", ifi.Name)
	}
	if ifi.Flags&net.FlagMulticast == 0 {
		return fmt.Errorf("interface %s is not multicast-capable", ifi.Name)
	}
	return nil
}

func multicastZones() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is6() && ip.IsLinkLocalUnicast() {
				out = append(out, ifi.Name)
				break
			}
		}
	}
	return out, nil
}

type vector interface {
	send(seq int) error

	read(buf []byte, deadline time.Time) (src netip.Addr, ok bool, err error)
	Close() error
}

const sweepProbes = 3

func runSweep(ctx context.Context, v vector, wait time.Duration, found func(netip.Addr)) error {
	defer v.Close()

	start := time.Now()
	final := start.Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(final) {
		final = dl
	}

	var spacing time.Duration
	if sweepProbes > 1 {
		spacing = wait / (2 * (sweepProbes - 1))
	}
	schedule := make([]time.Time, sweepProbes)
	for i := range schedule {
		schedule[i] = start.Add(time.Duration(i) * spacing)
	}

	sent := 0
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return nil
		}
		for sent < len(schedule) && !time.Now().Before(schedule[sent]) {
			sent++
			if err := v.send(sent); err != nil {

				if sent == 1 {
					return err
				}
				sent = len(schedule)
			}
		}
		deadline := final
		if sent < len(schedule) && schedule[sent].Before(final) {
			deadline = schedule[sent]
		}
		src, ok, err := v.read(buf, deadline)
		if err != nil {
			if isTimeout(err) {
				if time.Now().Before(final) {
					continue
				}
				return nil
			}
			return err
		}
		if ok {
			found(src)
		}
	}
}

func icmpSweep(ctx context.Context, group netip.Addr, zone string, opt Options, found func(netip.Addr)) error {
	v, err := newICMPVector(group, zone)
	if err != nil {
		return err
	}
	return runSweep(ctx, v, opt.wait(), found)
}

type icmpVector struct {
	conn *icmp.PacketConn
	dst  *net.UDPAddr
	id   int
}

func newICMPVector(group netip.Addr, zone string) (*icmpVector, error) {
	conn, err := icmp.ListenPacket("udp6", "::")

	id := 0
	if err != nil {
		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return nil, fmt.Errorf("no ICMPv6 socket (raw ICMPv6 needs root on this platform): %w", err)
		}
		id = 0x6f6f
	}
	return &icmpVector{conn: conn, dst: &net.UDPAddr{IP: group.AsSlice(), Zone: zone}, id: id}, nil
}

func (v *icmpVector) send(seq int) error {
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Body: &icmp.Echo{ID: v.id, Seq: seq, Data: []byte("oobscan link-local discovery")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = v.conn.WriteTo(b, v.dst)
	return err
}

func (v *icmpVector) read(buf []byte, deadline time.Time) (netip.Addr, bool, error) {
	if err := v.conn.SetReadDeadline(deadline); err != nil {
		return netip.Addr{}, false, err
	}
	n, peer, err := v.conn.ReadFrom(buf)
	if err != nil {
		return netip.Addr{}, false, err
	}

	msg, perr := icmp.ParseMessage(protocolICMPv6, buf[:n])
	if perr != nil || msg.Type != ipv6.ICMPTypeEchoReply {
		return netip.Addr{}, false, nil
	}
	src, ok := srcAddr(peer)
	return src, ok, nil
}

func (v *icmpVector) Close() error { return v.conn.Close() }

func rmcpSweep(ctx context.Context, group netip.Addr, zone string, opt Options, found func(netip.Addr)) error {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		return err
	}
	v := &rmcpVector{conn: conn, dst: &net.UDPAddr{IP: group.AsSlice(), Zone: zone, Port: opt.ipmiPort()}}
	return runSweep(ctx, v, opt.wait(), found)
}

type rmcpVector struct {
	conn *net.UDPConn
	dst  *net.UDPAddr
}

func (v *rmcpVector) send(seq int) error {
	for _, pkt := range [][]byte{

		ipmi.ASFPingPacket(byte(seq)),

		ipmi.GetChannelAuthCapsPacket(0x0e, 0x04),
	} {
		if _, err := v.conn.WriteTo(pkt, v.dst); err != nil {
			return err
		}
	}
	return nil
}

func (v *rmcpVector) read(buf []byte, deadline time.Time) (netip.Addr, bool, error) {
	if err := v.conn.SetReadDeadline(deadline); err != nil {
		return netip.Addr{}, false, err
	}
	n, peer, err := v.conn.ReadFromUDP(buf)
	if err != nil {
		return netip.Addr{}, false, err
	}

	if n < 4 || buf[0] != 0x06 {
		return netip.Addr{}, false, nil
	}
	src, ok := netip.AddrFromSlice(peer.IP)
	return src, ok, nil
}

func (v *rmcpVector) Close() error { return v.conn.Close() }

func srcAddr(peer net.Addr) (netip.Addr, bool) {
	switch p := peer.(type) {
	case *net.UDPAddr:
		return netip.AddrFromSlice(p.IP)
	case *net.IPAddr:
		return netip.AddrFromSlice(p.IP)
	}
	return netip.Addr{}, false
}

func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}
