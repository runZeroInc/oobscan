# OOBscan

> An exploration tool for (in)secure out-of-band management services.

OOBscan enumerates BMCs, serial-port servers, IP-KVMs, PDUs, and other
out-of-band management surfaces for protocol exposures, pre-auth information
leakage, default credentials, and known-vulnerable firmware. The BMC/IPMI
coverage ships enabled by default and drives the "Lights Out" Black Hat USA
2026 research.

## Status

This pre-release is missing detailed checks for vulnerabilities that are still going through the vendor notification and disclosure process.

## Build

```console
$ go build -o oobscan .
```

## Commands

`scan` is the flagship: point it at targets and it runs the full
identify -> checks -> creds pipeline. The remaining commands are focused tools
for working with scan results and for interacting with a single target.

```console
# Scan and inventory
$ oobscan scan        # comprehensive per-target pipeline (identify -> checks -> creds)
$ oobscan coverage    # print the OOB device/vendor inventory + registered check map
$ oobscan version

# Work with scan results (read a scan's *.jsonl)
$ oobscan convert     # normalize a corpus into oobscan JSONL; redact or audit it
$ oobscan replay      # re-run the record-pure detection logic over a corpus; diffable table
$ oobscan report      # build an interactive HTML exposure report (one or many corpora)
$ oobscan hashcrack   # crack leaked IPMI RAKP hashes offline (SHA1/MD5/SHA256); --show / --import-pot
$ oobscan hashdump    # export hashcat / John input files from RAKP hashes
$ oobscan explain     # render a markdown findings guide from a scan

# Interact with a single target (authenticated / targeted operations)
$ oobscan ipmi        # ipmitool-like IPMI command runner (mc/chassis/lan/fru/user/sol/raw/...)
$ oobscan redfish     # authenticated Redfish OEM operations
$ oobscan xdp         # Intel ASD / H3C RemoteXDP JTAG client
```

`oobscan convert` rewrites a corpus as native oobscan JSONL. It reads its own
output (migrating older records to the current rules) and the two runZero export
shapes (`--format rzsql`, `--format rzservices`), preserving every source
attribute and deriving the oobscan identity/findings/RAKP view on top. Two
transforms hang off the same pass: `--redact`, which renumbers addresses and
strips asset-identifying values to produce a shareable corpus, and `--quality`,
the contributor-facing QA audit for data-hygiene and coverage regressions
(formerly the `scanaudit` command).

`oobscan replay <corpus>` is the regression harness for that same logic. It
streams a corpus and re-evaluates everything that is a pure function of a stored
record -- the audit rules (contradiction detector, proof predicates,
silent-partial, binary-body, mangled-bytes, duplicate collapse), record
migration, and, on a runZero corpus, the finding emitters -- then prints one
tab-separated, key-sorted table. Build two binaries, replay the same corpus with
each, and `diff` the tables to see exactly which counts a change moved;
`--hosts <key>` prints the hosts behind one row so `comm` shows which hosts
gained or lost it, and `--field <check[.field]>` reports how much a field's value
actually varies. Nothing in `replay` opens a socket, so a change to a probe or a
live check cannot be measured this way -- that still needs a scan.

`oobscan report -o <dir> [Name=]<file.jsonl> ...` builds a self-contained,
offline-capable HTML report from one or more oobscan NDJSON corpora. (Point it
at oobscan output; run a runZero export through `oobscan convert` first.) Naming
two or more sources (`Internal=a.jsonl External=b.jsonl`) adds a cross-source
comparison that judges populations on prevalence (% of each source) while
showing absolute counts, so a small redacted internal fleet and a large internet
sweep compare cleanly. The report opens on 16:9, deck-ready overview slides
(arrow-navigable, presentable fullscreen, screenshottable to a 1920x1080 PNG);
scrollable, interactive detail views -- a per-category exposure heatmap, service
and port charts, findings, IPMI/RAKP, and a filterable per-host explorer whose
rows expand to full per-host findings and services -- sit under a per-source
menu. The payload is gzip-compressed in the page (decompressed via
`DecompressionStream`), so a 130k-host corpus is a ~12 MB bundle. `--systems`
caps the explorer rows (default 60k; aggregates always cover the whole corpus),
`--potfile` marks RAKP hashes already cracked in the pot, and a source produced
by `convert --redact` is detected and only its anonymized values are carried in.

Beyond the CLI, the scanner's building blocks -- GUID decoding, TLS shared-key
matching, and the per-protocol probes -- are also importable **library packages**
under `pkg/`; see [Using OOBscan as a library](#using-oobscan-as-a-library).

### How `scan` works

`scan` takes targets as arguments or via `-i` (file / `-` for stdin): single IPs,
hostnames, CIDRs (`10.0.0.0/24`), hyphen ranges (`10.0.0.1-20`), `host:port`, or
an **IPv6 link-local sweep** (`ff02::1%en0`, see below).
It fans out one **panic-isolated goroutine per host** (default 512, `-w`) and runs
a fixed pipeline on each:

1. **identify** -- probe IPMI/HTTP/TLS/Redfish/iLO/iDRAC/Lantronix/Moxa/..., fuse the
   signals into a device class + vendor + product (`pkg/identify`).
2. **device-specific checks** -- checks scoped to the identified vendor/class.
3. **cross-vendor / class checks** -- including the classic exposures: outdated
   libupnp via SSDP (CVE-2012-5958/5959), SNMP default community (`public`), SSH
   banner fingerprint + default-credential login, and the Supermicro `/PSBlock`
   cleartext credential store on TCP/49152 (CVE-2014-8272).
4. **`--ipmi-full`** (opt-in) -- walk the entire IPMI NetFn/Cmd/IPMB surface and
   run the slow Track B/C/D research sweeps (session-ID correlation, OEM NetFn
   reachability, IPMB satellite discovery). These are excluded from the default
   scan to keep it fast; the default runs the fast exposure checks only.
5. **`--ipmi-null-priv`** (opt-in, implied by `--ipmi-full`) -- when Get Channel
   Auth Caps advertises an enabled null or anonymous account, open an RMCP+
   session as it and **measure** the privilege it actually holds. The advertised
   bit is a configuration statement, not an impact statement: an account can be
   enabled yet clamped to privilege 0 with IPMI messaging off, unable to read
   sensors, FRU, the SEL, or even Get Device ID. Without the measurement
   `ipmi.authNull`/`ipmi.authAnon` stay LOW; a measured USER privilege or above
   raises them.

The interactive view shows progress, finding counts, and active phases.
`-v`/`--verbose` adds per-target and per-check logging on stderr. Ctrl-C cancels
the scan, flushes buffered output, and exits.

Default credentials are tried automatically for BMCs: the leaked RAKP-2 hash is
cracked **offline** (no lockout risk) against the vendor-prioritized knowledge
base, with a capped **online** RAKP-3/4 fallback for BMCs that don't leak
(`--disable-logins` disables all active logins).

Output is a live lipgloss TUI on a terminal, while newline-delimited JSON is
written to a file by default (set with `--output/-o`, or auto-created under
`~/.cache/oobscan` as `YYYYmmdd-<timestamp>.jsonl`). Use `--disable-output`
to skip automatic file creation when `--output` is not set:

```console
$ oobscan scan 10.0.0.0/24                      # interactive TUI
$ oobscan scan -o out.jsonl 10.0.0.0/16         # NDJSON to a file
$ oobscan scan 10.0.0.0/16                      # NDJSON auto file in cache dir
$ oobscan scan --disable-output 10.0.0.0/16     # no auto NDJSON file
$ oobscan scan --disable-logins 10.0.0.0/16 # passive-only (no active default login attempts)
$ oobscan scan --ipmi-full 10.0.0.22            # + full IPMI walk
$ oobscan scan -v 10.0.0.22                      # -v/--verbose: per-target identity + progress
```

#### IPv6 link-local sweeps

A management NIC answers on its IPv6 link-local address even when it has no
routable address at all -- freshly racked, no DHCP, or a management VLAN with no
addressing -- so an IPv6 multicast target is treated as a **sweep** rather than a
host. `oobscan scan ff02::1%en0` probes the all-nodes group on `en0` and scans
every link-local address that answers; drop the zone (`ff02::1`) to sweep every
up, multicast-capable interface that has a link-local address:

```console
$ oobscan scan ff02::1%en0                       # sweep en0, then scan what answers
$ oobscan scan --link-local-wait 8s ff02::1%en0  # longer listen window (busy segment)
$ oobscan scan ff02::1                           # sweep every eligible interface
$ oobscan ipmi ff02::1%en0 mc info               # same sweep, ipmi subcommand
$ oobscan scan 'fe80::dead:beef%en0'             # a link-local host directly
```

Two probes go out per interface (`pkg/discover`): an **ICMPv6 echo** to the group,
which every IPv6 node answers and which carries the sweep, and an **RMCP presence
ping + session-less Get Channel Auth Caps** on UDP/623, which additionally proves
a responder is a BMC. Both are read-only. Nodes stagger and rate-limit replies to
multicast (RFC 4443), so the sweep spreads several probes across the listen
window (`--link-local-wait`, default 3s) -- raise it if a device is missed. On
platforms where ICMPv6 datagram sockets are restricted the sweep falls back to a
raw socket and needs root; a bad zone is reported rather than silently swept on
the default interface.

Discovered targets keep their zone (`fe80::...%en0`) through dialing, URLs, and
the `host` field of the NDJSON output.

Captured RAKP hashes are written into each result's `rakp` records: the
`hashcat` field holds the ready-to-crack hashcat `-m 7300` line when one applies
(HMAC-SHA1); HMAC-MD5/SHA256 records omit it but keep the full reconstruction
material (SIDs, nonces, GUID, HMAC) for offline cracking with the
`pkg/ipmi` crack API.

`--verbose` logs to stderr only. It reports per-target progress without touching
the NDJSON stream or TUI.

## Using OOBscan as a library

Module path: `github.com/runZeroInc/oobscan`. The scanning pipeline and every
research capability is available as an importable package; the CLI is a thin
front-end over them. Highlights:

| Capability | Package | Entry points |
|---|---|---|
| Offline RAKP crack + hashcat `-m 7300` export | `pkg/ipmi` | `CrackRAKP`, `(*RAKPResult).Hashcat` |
| Credential defaults + permutation engine | `pkg/creds` | `Table`, `CredsFor`, `Permute` |
| Concurrent target engine and result model | `pkg/engine` | `New`, `Run`, `Target`, `Finding` |
| IPv6 link-local host discovery (multicast sweep) | `pkg/discover` | `LinkLocal`, `ResolveSpecs`, `IsSpec` |
| IPv6-safe host:port and URL formatting (zones) | `pkg/netaddr` | `DialHostPort`, `URL`, `URLHostPort` |
| BMC System GUID decoder (vendor taxonomy) | `pkg/guid` | `Decode`, `DecodeHex` |
| Remotely-detectable BMC/webapp CVE knowledge base | `pkg/check`, `pkg/ilo` | `check.Register` HTTP CVE checks, `ilo` CVE map |
| Default/shared TLS cert + SPKI shared-key matching | `pkg/tlscert` | `Inspect`, `ClassifyIdentity` |
| Registered security-check registry | `pkg/check` | `check.Register`, `check.All` |
| Device/vendor/product inventory | `pkg/oob` | `oob.Vendors`, `oob.ByVendor` |
| Per-protocol probes | `pkg/ipmi`, `pkg/redfish`, `pkg/ilo`, `pkg/idrac`, `pkg/tlscert`, `pkg/wsman`, `pkg/amt`, `pkg/snmp`, `pkg/ssdp`, `pkg/slp`, `pkg/lantronix`, `pkg/moxa` | package-level probe funcs |

> Note: these packages are importable but are not a committed-stable public API
> map and stability notes, and [`examples/`](examples/) for runnable snippets.

## Extending

- **New credential**: add one row to `creds.Table` (`pkg/creds/table.go`).
- **New check**: `check.Register(...)` from an `init()` in `pkg/check`, with an
  `Applicability` naming the target vendors/classes (or `CrossVendor`). The pipeline
  picks it up by applicability -- no wiring changes.
- **New device class**: add the `DeviceClass` const (`pkg/engine`) and its
  `oob.Category` mapping (`pkg/identify/class.go`).
- **New protocol probe**: add `pkg/<proto>/`, then a collector in
  `pkg/identify/collectors.go` that fuses its signals into identification.

## Protocols covered

| Protocol | Port(s) | Package |
|---|---|---|
| IPMI 1.5 / RMCP ASF ping | 623/udp | `pkg/ipmi` |
| IPMI 2.0 RMCP+ RAKP (multi-user/multi-cipher) | 623/udp | `pkg/ipmi` |
| Get Device ID + IANA manufacturer->vendor | 623/udp | `pkg/ipmi` |
| Get Channel Cipher Suites enumeration (paged) | 623/udp | `pkg/ipmi` |
| Supermicro USBAnywhere virtual media (CVE-2019-16649/50) | 623/tcp | `pkg/ipmi` |
| Default/shared TLS certificate + weak-key fingerprint | 443/tcp | `pkg/tlscert` |
| BMC HTTP/TLS/SSH vendor fingerprints (recog-derived) | 443/22/tcp | `pkg/bmcfp` |
| Redfish + AMI CVE-2023-34329 / CVE-2024-54085 / :9080 no-XFF bypass | 443/9080/tcp | `pkg/redfish` |
| Firmware-derived HTTP/CGI/RPC sweep | 80/tcp, 443/tcp | `pkg/httpscan` |
| HPE iLO `/xmldata` | 443/tcp | `pkg/ilo` |
| Dell iDRAC `/data?get=fwVersion` etc. | 443/tcp | `pkg/idrac` |
| WS-Management Identify | 443/5986/16993 | `pkg/wsman` |
| Intel AMT + CVE-2017-5689 | 16992/16993 | `pkg/amt` |
| SNMP v1/v2c sysDescr / sysObjectID | 161/udp | `pkg/snmp` |
| SSDP M-SEARCH | 1900/udp | `pkg/ssdp` |
| SLPv2 SrvRqst | 427/udp | `pkg/slp` |
| Lantronix Setup Protocol | 30718/udp | `pkg/lantronix` |
| Moxa DeviceSearch | 4800/udp | `pkg/moxa` |
| SSH (sshamble JSONL import) | 22/tcp | `pkg/ssh` |

Run `oobscan coverage` for the full vendor / product table and the registered
security-check map.

Implementation coverage is tracked in
[`COVERAGE.md`](COVERAGE.md).

## Capability model

Checks are organized around what an unauthenticated network client can learn or do
against a BMC:

- **Discovery** -- RMCP ping, Get Channel Auth Caps, Get Device ID, paged
  cipher-suite enumeration, Get System GUID.
- **Fingerprint** -- vendor/product/firmware from the Device-ID IANA manufacturer
  ID, the Get Channel Auth Caps OEM ID, the System GUID taxonomy (Dell service
  tag / HPE part-country-serial / Supermicro board-MAC / UUIDv1 node ID), and
  recog-derived HTTP/TLS/SSH signatures (`pkg/bmcfp`).
- **Exposure** -- cipher-suite 0 (advertise vs. live), weak/legacy cipher suites,
  RAKP-2 hash disclosure (CVE-2013-4786), "accepts any username", null/anonymous
  users, IPMI 1.5 plaintext/MD2, shared/default TLS keys, USBAnywhere, Redfish
  auth-bypass, and version-matched known CVEs.
- **Weak credentials** -- RAKP hash extraction across the default-username list,
  offline crack against vendor defaults plus a rules-driven permutation engine
  (case / leetspeak / word-doubling / year-suffix variants).

## Design notes

- Single static Go binary, zero runtime deps.
- Typed `check.Register(Check{...})` registry; checks are selectable via
  `--checks` and `--categories`.
- NDJSON output is the machine-readable source of truth.
- Single IPv6 targets are supported. CIDR and hyphen-range expansion is IPv4-only.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
# oobscan
