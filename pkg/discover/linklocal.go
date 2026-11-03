// Package discover turns an IPv6 multicast target spec into a list of real hosts to
// scan. A management NIC that was never given an address still answers on its IPv6
// link-local address, so sweeping the all-nodes group on an interface reaches a
// directly-cabled or same-VLAN BMC with no DHCP and no known subnet.
//
// Two probes go out per interface, neither of which writes to the target. ICMPv6
// echo to the group carries the sweep; nodes delay multicast replies by a random
// interval (RFC 4443) and rate-limit further ones, which is why the sweep spreads
// probes over a listen window of seconds. An RMCP presence ping plus sessionless Get
// Channel Auth Caps to UDP/623 is a bonus rather than coverage, since whether a
// multicast datagram reaches a socket that never joined the group is stack-dependent.
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

// AllNodes is the IPv6 all-nodes link-local multicast group: every IPv6 node on
// the link is a member, which makes it the broadest link-local sweep available.
const AllNodes = "ff02::1"

// protocolICMPv6 is the IANA IP protocol number for ICMPv6, which is what
// icmp.ParseMessage expects to select its parser.
const protocolICMPv6 = 58

// DefaultWait is how long a sweep listens for replies after its last probe.
// Sized for RFC 4443's random multicast-response delay (up to a second on
// common stacks) plus a slow BMC's turnaround.
const DefaultWait = 3 * time.Second

// Options parameterizes a link-local sweep.
type Options struct {
	Wait     time.Duration // listen window after the last probe (0 = DefaultWait)
	IPMIPort int           // RMCP/IPMI port to probe (0 = 623)
	SkipICMP bool          // skip the ICMPv6 echo vector (leaves the RMCP vector)
	SkipIPMI bool          // skip the RMCP/IPMI vector (leaves the ICMPv6 vector)
	Log      func(string)  // optional progress sink (stderr in the CLI)
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

// Responder is one host that answered a sweep.
type Responder struct {
	Addr netip.Addr // link-local address including its zone, e.g. fe80::1%en0
	Via  []string   // probes that elicited a reply: "icmp6", "rmcp"
}

// Host renders the responder as a scan target spec.
func (r Responder) Host() string { return r.Addr.String() }

// IsSpec reports whether tok is an IPv6 multicast target spec (ff00::/8),
// optionally zoned: "ff02::1%en0", "ff02::1", "[ff02::1%en0]". Such a spec names
// a discovery sweep rather than a host -- nothing listens on a multicast
// address, so scanning it directly would always come back empty.
func IsSpec(tok string) bool {
	addr, _, ok := parseSpec(tok)
	return ok && addr.Is6() && addr.IsMulticast()
}

// parseSpec splits a multicast spec into its group and zone. The zone is
// returned separately because it is the interface selector for the sweep, not
// part of the group address.
func parseSpec(tok string) (group netip.Addr, zone string, ok bool) {
	t := strings.TrimSpace(tok)
	t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	addr, err := netip.ParseAddr(t)
	if err != nil {
		return netip.Addr{}, "", false
	}
	return addr.WithZone(""), addr.Zone(), true
}

// LinkLocal sweeps the multicast group named by spec and returns the hosts that
// answered. An unzoned spec ("ff02::1") sweeps every eligible interface: up,
// multicast-capable, non-loopback, and carrying an IPv6 link-local address.
// Order is randomized by the caller's target expansion, so results come back
// sorted for stable logging.
func LinkLocal(ctx context.Context, spec string, opt Options) ([]Responder, error) {
	group, zone, ok := parseSpec(spec)
	if !ok || !group.Is6() || !group.IsMulticast() {
		return nil, fmt.Errorf("not an IPv6 multicast spec: %q", spec)
	}
	zones := []string{zone}
	if zone != "" {
		// Validate the zone up front: an unknown zone name resolves to interface
		// index 0, which silently sends the sweep out the default interface
		// instead of the one the operator named.
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
	// Every vector failing is a real error (no raw-socket permission, interface
	// gone); some vectors failing with hosts found is normal and only logged.
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for _, err := range errs {
		opt.log("link-local discovery: %v", err)
	}
	return out, nil
}

// hitSet collects the sources seen by the sweep vectors, which run concurrently
// across vectors and interfaces.
type hitSet struct {
	mu   sync.Mutex
	hits map[netip.Addr]map[string]bool
}

// recorder returns the callback a vector hands each reply source. Sources that
// cannot be scan targets -- an IPv4 mapping, the group itself, the unspecified
// address -- are dropped rather than turned into dead targets.
func (h *hitSet) recorder(zone, via string) func(netip.Addr) {
	return func(src netip.Addr) {
		src = src.Unmap()
		if !src.IsValid() || src.Is4() || src.IsMulticast() || src.IsUnspecified() {
			return
		}
		// Zone the address so it stays dialable: a link-local address means
		// nothing without the interface it was seen on.
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

// responders renders the collected hits, sorted so logs and target order are
// stable across runs.
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

// ResolveSpecs replaces every multicast discovery spec in hosts with the hosts
// that answered a sweep of it, leaving ordinary targets untouched and in place.
// Duplicate results (the same BMC answering on two interfaces of the same
// segment, or a discovered address also given explicitly) collapse to one entry.
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

// checkZone resolves a zone (an interface name, or a numeric index as the
// sockaddr form allows) and reports why it cannot carry a sweep. Without this,
// net's zone cache maps an unknown name to index 0 and the probes leave by the
// default route -- a typo'd interface would look like an empty segment.
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

// multicastZones lists the interfaces worth sweeping when a spec carries no
// zone: up, multicast-capable, not loopback, and holding an IPv6 link-local
// address (without one the kernel has no source address for the probe).
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

// vector is one discovery probe: a socket that can emit the probe repeatedly and
// hand back the source address of each reply it recognizes. runSweep drives it,
// so the two vectors share their probe pacing and their listen window.
type vector interface {
	// send emits probe number seq (1-based).
	send(seq int) error
	// read returns the source of the next recognized reply. ok is false for a
	// packet that is not a reply to this probe (parse failure, wrong ICMP type,
	// non-RMCP datagram); a read timeout is returned as a net.Error.
	read(buf []byte, deadline time.Time) (src netip.Addr, ok bool, err error)
	Close() error
}

// sweepProbes is how many times each vector probes the group. More than one
// because stacks rate-limit replies to a multicast destination and drop the
// rest, so a single probe under-reports a populated segment.
const sweepProbes = 3

// runSweep probes the group repeatedly while reading replies, spreading the
// probes over the first half of the listen window so the last one still has time
// to be answered. Reads and sends interleave on one goroutine: the read deadline
// is capped at the next probe time, and a timeout there just means "time to send
// again", not "done".
func runSweep(ctx context.Context, v vector, wait time.Duration, found func(netip.Addr)) error {
	defer v.Close()

	start := time.Now()
	final := start.Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(final) {
		final = dl
	}
	// Probes at 0, wait/4, wait/2 ... : evenly spread over the first half of the
	// window, so even the last one has half the window left to be answered.
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
				// A first probe that cannot be sent is a broken vector (no route,
				// bad zone, no permission). A later one failing after replies are
				// already arriving is not worth aborting the window for.
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
					continue // probe boundary, not the end of the window
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

// icmpSweep probes the group with ICMPv6 echo requests and reports the source of
// every echo reply. Every compliant IPv6 node answers, so this is the vector
// that finds hosts whose management services are unknown or firewalled off.
func icmpSweep(ctx context.Context, group netip.Addr, zone string, opt Options, found func(netip.Addr)) error {
	v, err := newICMPVector(group, zone)
	if err != nil {
		return err
	}
	return runSweep(ctx, v, opt.wait(), found)
}

// icmpVector is the ICMPv6 echo vector.
type icmpVector struct {
	conn *icmp.PacketConn
	dst  *net.UDPAddr
	id   int
}

// newICMPVector opens an ICMPv6 listener, preferring the unprivileged datagram
// form ("udp6", available to a normal user on macOS and on Linux when
// ping_group_range allows it) and falling back to a raw socket, which needs root.
func newICMPVector(group netip.Addr, zone string) (*icmpVector, error) {
	conn, err := icmp.ListenPacket("udp6", "::")
	// An unprivileged ICMP datagram socket has its echo ID rewritten by the
	// kernel, so replies are matched on type alone there; the raw socket keeps a
	// recognizable ID. Either way a stray echo reply from another host on the
	// link is still a host worth scanning, so the ID is not a filter.
	id := 0
	if err != nil {
		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return nil, fmt.Errorf("no ICMPv6 socket (raw ICMPv6 needs root on this platform): %w", err)
		}
		id = 0x6f6f // "oo"
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
	// ParseMessage takes the IP protocol number (58 for ICMPv6), not an ICMP
	// type: pass a type here and every reply parses as ICMPv4 and is dropped.
	msg, perr := icmp.ParseMessage(protocolICMPv6, buf[:n])
	if perr != nil || msg.Type != ipv6.ICMPTypeEchoReply {
		return netip.Addr{}, false, nil
	}
	src, ok := srcAddr(peer)
	return src, ok, nil
}

func (v *icmpVector) Close() error { return v.conn.Close() }

// rmcpSweep probes the group with the RMCP presence ping and a session-less Get
// Channel Authentication Capabilities on UDP/623, and reports the source of every
// RMCP reply. It finds a BMC whose stack ignores multicast ICMP, and a reply here
// also says the responder is a BMC rather than any node on the segment.
func rmcpSweep(ctx context.Context, group netip.Addr, zone string, opt Options, found func(netip.Addr)) error {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		return err
	}
	v := &rmcpVector{conn: conn, dst: &net.UDPAddr{IP: group.AsSlice(), Zone: zone, Port: opt.ipmiPort()}}
	return runSweep(ctx, v, opt.wait(), found)
}

// rmcpVector is the RMCP/IPMI vector.
type rmcpVector struct {
	conn *net.UDPConn
	dst  *net.UDPAddr
}

func (v *rmcpVector) send(seq int) error {
	for _, pkt := range [][]byte{
		// The message tag carries the probe number so a pong can be matched to
		// its ping in a packet capture of the sweep.
		ipmi.ASFPingPacket(byte(seq)),
		// Channel 0x0e = "this channel", admin privilege: the same session-less
		// read the scan pipeline opens every IPMI conversation with.
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
	// RMCP version 0x06 in byte 0 is the cheapest check that the reply came from
	// an RMCP speaker and not from some other listener on the segment.
	if n < 4 || buf[0] != 0x06 {
		return netip.Addr{}, false, nil
	}
	src, ok := netip.AddrFromSlice(peer.IP)
	return src, ok, nil
}

func (v *rmcpVector) Close() error { return v.conn.Close() }

// srcAddr extracts the source address from an ICMP peer, which is a *net.UDPAddr
// on an unprivileged datagram socket and a *net.IPAddr on a raw one.
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
