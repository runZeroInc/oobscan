package ipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

type postAuthTraceKey struct{}

// WithPostAuthTrace attaches an optional trace callback used for verbose,
// step-by-step post-auth progress reporting.
func WithPostAuthTrace(ctx context.Context, trace func(string, ...any)) context.Context {
	if trace == nil {
		return ctx
	}
	return context.WithValue(ctx, postAuthTraceKey{}, trace)
}

func postAuthTracef(ctx context.Context, format string, args ...any) {
	if ctx == nil {
		return
	}
	v := ctx.Value(postAuthTraceKey{})
	if v == nil {
		return
	}
	if fn, ok := v.(func(string, ...any)); ok && fn != nil {
		fn(format, args...)
	}
}

// AuthFlow captures the exact authenticated path selected for post-session
// inventory collection.
type AuthFlow struct {
	Version     string `json:"version"` // "1.5" or "2.0"
	Mode        string `json:"mode"`    // cred | authNone | cipherZero | smcrakpFixedKey | openbmcSetup | openbmcRelabel | iloRakpNoneBypass
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	RelabelUser string `json:"relabelUser,omitempty"`
	// StaleBMCRand is the 16-byte bmcRandomNum recovered by a successful OpenBMC
	// default-userKey bypass. It stands in for a password on the openbmcBypassRelabel
	// path: with it the session reopens at CALLBACK with no credential at all.
	StaleBMCRand []byte      `json:"staleBmcRand,omitempty"`
	AuthType     byte        `json:"authType,omitempty"` // v1.5
	Suite        CipherAlgos `json:"suite"`              // v2.0
	Source       string      `json:"source,omitempty"`   // evidence tag
}

// TableReporter is implemented by a workflow result that renders itself, for the
// session-backed commands whose report shape does not fit the generic
// key/value or slice rendering (the Supermicro command-injection validators,
// whose verdict and safety fields need their own layout). A result that does
// not implement it falls through to the generic renderer.
type TableReporter interface {
	SMCPrintTable(w io.Writer) error
}

// MCInfo is the parsed equivalent of the key fields from ipmitool mc info.
//
// FirmwareRevision is the two-component value the Get Device ID revision bytes
// carry on their own. FirmwareRevisionFull is the vendor-published version
// reconstructed from those bytes plus the auxiliary revision, and is empty when
// the vendor's auxiliary encoding is not confirmed; AuxFirmwareHex holds the raw
// auxiliary bytes either way. See FormatFirmwareRevisionFull.
type MCInfo struct {
	DeviceID             byte   `json:"deviceId"`
	DeviceRevision       byte   `json:"deviceRevision"`
	FirmwareRevision     string `json:"firmwareVersion"`
	FirmwareRevisionFull string `json:"firmwareVersionFull,omitempty"`
	IPMIVersion          string `json:"ipmiVersion"`
	ManufacturerID       uint32 `json:"manufacturerId"`
	ManufacturerName     string `json:"manufacturerName,omitempty"`
	ProductID            uint16 `json:"productId"`
	AuxFirmwareHex       string `json:"auxFirmwareHex,omitempty"`
	AdditionalSupport    byte   `json:"additionalSupport"`
}

// UserEntry is a compact view of one user slot (ipmitool user list equivalent).
type UserEntry struct {
	ID       int    `json:"id"`
	Name     string `json:"name,omitempty"`
	Priv     string `json:"priv"`
	Enabled  bool   `json:"enabled"`
	LinkAuth bool   `json:"linkAuth"`
	IPMIAuth bool   `json:"ipmiAuth"`
	Callin   bool   `json:"callin"`
	Raw      string `json:"raw,omitempty"`
}

// FRUField is one parsed string field from the FRU areas.
type FRUField struct {
	DeviceID int    `json:"deviceId,omitempty"`
	Area     string `json:"area"`
	Index    int    `json:"index"`
	Name     string `json:"name,omitempty"`
	Value    string `json:"value"`
}

// ChassisStatus mirrors key output from ipmitool chassis status.
type ChassisStatus struct {
	PowerOn           bool   `json:"powerOn"`
	PowerOverload     bool   `json:"powerOverload"`
	PowerInterlock    bool   `json:"powerInterlock"`
	MainPowerFault    bool   `json:"mainPowerFault"`
	PowerControlFault bool   `json:"powerControlFault"`
	PowerRestore      string `json:"powerRestorePolicy,omitempty"`
	LastEvent         string `json:"lastPowerEvent,omitempty"`
	IdentifyOn        bool   `json:"identifyOn"`
	CoolingFault      bool   `json:"coolingFault"`
	DriveFault        bool   `json:"driveFault"`
	Raw               string `json:"raw,omitempty"`
}

// CipherAttempt records one RMCP+ cipher-suite post-auth attempt.
type CipherAttempt struct {
	Suite     int    `json:"suite"`
	Auth      byte   `json:"auth"`
	Integrity byte   `json:"integrity"`
	Conf      byte   `json:"conf"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// OpenBMCSetupData is the privileged local-command data reachable in the
// phosphor-net-ipmid setup state after RAKP-1 and before RAKP-3.
type OpenBMCSetupData struct {
	PrivilegeQueryCC       byte   `json:"privilegeQueryCc"`
	PrivilegeQueryDataHex  string `json:"privilegeQueryDataHex,omitempty"`
	PayloadStatusCC        byte   `json:"payloadStatusCc"`
	PayloadStatusDataHex   string `json:"payloadStatusDataHex,omitempty"`
	PayloadInfoCC          byte   `json:"payloadInfoCc,omitempty"`
	PayloadInfoDataHex     string `json:"payloadInfoDataHex,omitempty"`
	ProviderGetDeviceIDCC  byte   `json:"providerGetDeviceIdCc,omitempty"`
	ProviderGetDeviceIDHex string `json:"providerGetDeviceIdHex,omitempty"`
	ProviderBlocked        bool   `json:"providerBlocked"`
	Error                  string `json:"error,omitempty"`
}

// PostAuthCollection is the aggregate post-session inventory payload.
type PostAuthCollection struct {
	Flow            AuthFlow          `json:"flow"`
	CipherMatrix    []CipherAttempt   `json:"cipherMatrix,omitempty"`
	SetPrivAttempts []SetPrivAttempt  `json:"setPrivAttempts,omitempty"`
	OpenBMCSetup    *OpenBMCSetupData `json:"openbmcSetup,omitempty"`
	MCInfo          *MCInfo           `json:"mcInfo,omitempty"`
	Chassis         *ChassisStatus    `json:"chassis,omitempty"`
	Users           []UserEntry       `json:"users,omitempty"`
	LAN             map[string]string `json:"lan,omitempty"`
	LAN6            map[string]string `json:"lan6,omitempty"`
	FRU             []FRUField        `json:"fru,omitempty"`
	// CommandProtection records the wire protection used for the in-session
	// enumeration commands: "cleartext" (H3 path), "integrity+conf", or "none".
	CommandProtection string `json:"commandProtection,omitempty"`
	// Error stays out of the JSON: it is a scan-side operational string, not something
	// the device reported. Its content still reaches the output as the
	// ipmi.postAuthEnum finding's coverageError field.
	Error string `json:"-"`
	// Completed, Empty and IncompleteAt are serialized: they are the coverage record, not
	// operational noise. Every section field is omitempty, so without them an attempted
	// section that came back empty is indistinguishable from one never attempted, and a
	// run that lost fru to a deadline looks like a board with no FRU to read.
	//
	// Completed holds only the sections that produced data. Empty holds the sections that
	// were read and answered with nothing, which is a different claim: a board with no FRU
	// EEPROM belongs in Empty, a board whose FRU read never happened belongs in neither.
	Completed    []string `json:"completed,omitempty"`
	Empty        []string `json:"empty,omitempty"`
	IncompleteAt string   `json:"incompleteAt,omitempty"`
}

// recordSection files an attempted inventory section under Completed when it produced
// data and Empty when it did not. Recording an empty section as completed tells a
// consumer the section was measured and had nothing, which is a claim the collector
// cannot make when the commands were refused.
func recordSection(out *PostAuthCollection, name string, hasData bool) {
	if out == nil {
		return
	}
	if hasData {
		out.Completed = append(out.Completed, name)
		return
	}
	out.Empty = append(out.Empty, name)
}

// MarshalJSON normalizes dynamic LAN/LAN6 map keys to camelCase at the scan
// output boundary while preserving the in-memory IPMI names used by parsers.
func (p PostAuthCollection) MarshalJSON() ([]byte, error) {
	type postAuthJSON struct {
		Flow              AuthFlow          `json:"flow"`
		CipherMatrix      []CipherAttempt   `json:"cipherMatrix,omitempty"`
		SetPrivAttempts   []SetPrivAttempt  `json:"setPrivAttempts,omitempty"`
		OpenBMCSetup      *OpenBMCSetupData `json:"openbmcSetup,omitempty"`
		MCInfo            *MCInfo           `json:"mcInfo,omitempty"`
		Chassis           *ChassisStatus    `json:"chassis,omitempty"`
		Users             []UserEntry       `json:"users,omitempty"`
		LAN               map[string]string `json:"lan,omitempty"`
		LAN6              map[string]string `json:"lan6,omitempty"`
		FRU               []FRUField        `json:"fru,omitempty"`
		CommandProtection string            `json:"commandProtection,omitempty"`
		// The coverage record; the operational Error string is deliberately not here.
		// See the struct comment.
		Completed    []string `json:"completed,omitempty"`
		Empty        []string `json:"empty,omitempty"`
		IncompleteAt string   `json:"incompleteAt,omitempty"`
	}
	return json.Marshal(postAuthJSON{
		Flow:              p.Flow,
		CipherMatrix:      p.CipherMatrix,
		SetPrivAttempts:   p.SetPrivAttempts,
		OpenBMCSetup:      p.OpenBMCSetup,
		MCInfo:            p.MCInfo,
		Chassis:           p.Chassis,
		Users:             p.Users,
		LAN:               engine.CanonicalStringMap(p.LAN),
		LAN6:              engine.CanonicalStringMap(p.LAN6),
		FRU:               p.FRU,
		CommandProtection: p.CommandProtection,
		Completed:         p.Completed,
		Empty:             p.Empty,
		IncompleteAt:      p.IncompleteAt,
	})
}

// adminishUsernames are the account names that conventionally hold Administrator
// on a BMC, most-privileged first. Used only to order candidates: the real
// privilege is whatever the BMC grants, and a low-priv session is still tried.
var adminishUsernames = []string{"admin", "administrator", "root", "sysadmin", "supervisor", "operator"}

// UsernamePrivRank scores how likely an account is to hold Administrator. Lower is
// better, so it sorts naturally. An unknown name ranks between the named admins and
// the null/anonymous account. Exported so the Redfish post-auth stage can try the
// most-privileged recovered account first.
func UsernamePrivRank(user string) int {
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "" {
		return 99 // null/anonymous: least likely to be privileged
	}
	for i, a := range adminishUsernames {
		if u == a {
			return i
		}
	}
	return len(adminishUsernames) + 1
}

// SelectPostAuthFlows returns every viable post-auth flow, best-privilege-first, so the
// caller can fall back down the list: real credentials (admin-looking accounts first),
// then the vendor escalation chains, then forged sessions, no-auth last.
//
// Ordering matters more than it looks. A no-auth session sits at whatever privilege the
// BMC gives an unauthenticated caller, so Get Device ID / chassis / user-list / FRU come
// back cc=0xd4 while only the lower-privilege LAN reads succeed.
func SelectPostAuthFlows(auth *AuthReport, v15 *V15Report) []AuthFlow {
	suite := CipherAlgos{Suite: 1, Auth: RAKPHMACSHA1, Integrity: IntegrityNone, Conf: ConfNone}
	if auth != nil && auth.Suite != nil {
		suite = *auth.Suite
	}

	var creds20, escalations, forged, noAuth []AuthFlow

	if auth != nil {
		// Real 2.0 credentials, admin-looking accounts first.
		verified := make([]CrackResult, 0, len(auth.Cracked))
		for _, cr := range auth.Cracked {
			if cr.Verified {
				verified = append(verified, cr)
			}
		}
		sort.SliceStable(verified, func(i, j int) bool {
			return UsernamePrivRank(verified[i].Username) < UsernamePrivRank(verified[j].Username)
		})
		for _, cr := range verified {
			if cr.PasswordType == "smcrakp-fixed-key" {
				// Only worth running when the H3 bypass is command-exploitable: when the BMC
				// enforces per-session integrity (X14/OpenBMC) the session forges but no
				// command executes, so there is nothing to enumerate.
				if cr.CommandCapable {
					forged = append(forged, AuthFlow{
						Version: "2.0", Mode: "smcrakpFixedKey", Username: cr.Username,
						Suite: suite, Source: "ipmi.auth.smcrakpBypass",
					})
				}
				continue
			}
			creds20 = append(creds20, AuthFlow{
				Version: "2.0", Mode: "cred", Username: cr.Username, Password: cr.Password,
				Suite: suite, Source: "ipmi.auth.defaultCreds",
			})
		}
		// Privilege escalation: a credential we hold may be clamped to a low privilege
		// while an Administrator account merely named in RAKP-1 raises the session. The
		// escalation is attempted per low-priv credential, seeded with the most
		// admin-looking account name we know of on this host.
		if adminUser := postAuthEscalationAdminUser(auth); adminUser != "" {
			for _, f := range creds20 {
				if strings.EqualFold(f.Username, adminUser) {
					continue // already the admin account; nothing to escalate to
				}
				escalations = append(escalations, AuthFlow{
					Version: "2.0", Mode: "smcReservedRole",
					Username: f.Username, Password: f.Password, RelabelUser: adminUser,
					Suite: suite, Source: "ipmi.smc.rakpReservedRole",
				})
			}
		}
		if auth.CipherZero {
			noAuth = append(noAuth, AuthFlow{
				Version: "2.0", Mode: "cipherZero",
				Suite:  CipherAlgos{Suite: 0, Auth: RAKPNone, Integrity: IntegrityNone, Conf: ConfNone},
				Source: "ipmi.auth.cipherZero",
			})
		}
	}

	// Real 1.5 credentials rank with the other real credentials; 1.5 authNone is
	// no-auth and goes to the back with cipherZero.
	if v15 != nil && v15.DefaultCred != nil {
		at := IPMI15AuthMD5
		switch v15.DefaultCred.Via {
		case "md2":
			at = IPMI15AuthMD2
		case "straight":
			at = IPMI15AuthPass
		}
		creds20 = append(creds20, AuthFlow{
			Version: "1.5", Mode: "cred",
			Username: v15.DefaultCred.Username, Password: v15.DefaultCred.Password,
			AuthType: at, Source: "ipmi.v15.defaultCreds",
		})
	}
	if v15 != nil && v15.AuthNoneOK {
		noAuth = append(noAuth, AuthFlow{
			Version: "1.5", Mode: "authNone", AuthType: IPMI15AuthNone, Source: "ipmi.v15.authNone",
		})
	}

	out := make([]AuthFlow, 0, len(creds20)+len(escalations)+len(forged)+len(noAuth))
	out = append(out, creds20...)
	out = append(out, escalations...)
	out = append(out, forged...)
	return append(out, noAuth...)
}

// postAuthEscalationAdminUser returns the most admin-looking account name observed on
// this host, from any RAKP result, not just the cracked ones. Naming an Administrator
// account in RAKP-1 needs no password, which is what makes the reserved-role escalation
// reachable with only a low-privilege credential.
func postAuthEscalationAdminUser(auth *AuthReport) string {
	if auth == nil {
		return ""
	}
	best, bestRank := "", len(adminishUsernames)+1
	for _, r := range auth.Results {
		if rank := UsernamePrivRank(r.Username); rank < bestRank {
			best, bestRank = r.Username, rank
		}
	}
	for _, cr := range auth.Cracked {
		if rank := UsernamePrivRank(cr.Username); rank < bestRank {
			best, bestRank = cr.Username, rank
		}
	}
	return best
}

// SelectPostAuthFlow chooses the single best authenticated flow. Retained for
// callers that do not walk the fallback list; prefer SelectPostAuthFlows.
func SelectPostAuthFlow(auth *AuthReport, v15 *V15Report) (AuthFlow, bool) {
	flows := SelectPostAuthFlows(auth, v15)
	if len(flows) == 0 {
		return AuthFlow{}, false
	}
	return flows[0], true
}

type cmdRunner interface {
	Exec(netfn, cmd byte, data []byte) (byte, []byte, error)
	Close()
}

type v15Runner struct {
	client     *Client
	sess       *Session15
	cmdRetries int
}

func (r *v15Runner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if r.client == nil || r.sess == nil {
		return 0xff, nil, fmt.Errorf("v15 runner closed")
	}
	retries := r.cmdRetries
	if retries <= 0 {
		retries = 1
	}
	var (
		cc  byte
		out []byte
		err error
	)
	for attempt := 0; attempt < retries; attempt++ {
		cc, out, err = sendInSession(r.client, r.sess, netfn, cmd, data)
		if err == nil || !isTimeoutErr(err) {
			return cc, out, err
		}
	}
	return cc, out, err
}

func (r *v15Runner) Close() {
	if r == nil || r.sess == nil {
		return
	}
	if r.client != nil {
		r.client.Close()
	}
	CloseSession15(r.client.Host, r.client.Port, r.sess, r.client.Timeout)
	r.client = nil
	r.sess = nil
}

// CollectPostAuthInventory executes authenticated read-only IPMI inventory
// commands (mc info, user list, lan/lan6 print subset, fru fields).
func CollectPostAuthInventory(ctx context.Context, host string, port int, flow AuthFlow, timeout time.Duration) (*PostAuthCollection, error) {
	out := &PostAuthCollection{Flow: flow}
	postAuthTracef(ctx, "inventory start host=%s port=%d flow=%s/%s user=%s source=%s", host, port, flow.Version, flow.Mode, flow.Username, flow.Source)
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	opTimeout := effectivePostAuthOpTimeout(timeout)
	if flow.Mode == "smcrakpFixedKey" || flow.Mode == "openbmcSetup" || flow.Mode == "openbmcRelabel" || flow.Mode == "iloRakpNoneBypass" {
		opTimeout = timeout
		if opTimeout <= 0 {
			opTimeout = 6 * time.Second
		}
		if opTimeout > 12*time.Second {
			opTimeout = 12 * time.Second
		}
	}
	postAuthTracef(ctx, "session open start timeout=%s", opTimeout)
	openStart := time.Now()
	// Enumeration prefers the cleartext (H3) command path and falls back to negotiated
	// integrity+confidentiality, so {3,17}-restricted ATEN BMCs still enumerate while a BMC
	// that does enforce per-session protection is handled correctly. A SMCRAKP-forged
	// session has no valid K1/K2, so its inventory is forced cleartext: the only path the H3
	// bypass can use, and the one whose success defines exploitability.
	prot := protectionAuto
	if flow.Mode == "smcrakpFixedKey" || flow.Mode == "openbmcSetup" || flow.Mode == "iloRakpNoneBypass" {
		prot = protectionCleartext
	}
	r, err := openRunner(host, port, flow, opTimeout, prot)
	if err != nil {
		postAuthTracef(ctx, "session open failed elapsed=%s err=%v", time.Since(openStart).Round(time.Millisecond), err)
		out.IncompleteAt = "sessionOpen"
		out.Error = "sessionOpen: " + err.Error()
		return out, err
	}
	postAuthTracef(ctx, "session open success elapsed=%s", time.Since(openStart).Round(time.Millisecond))
	defer r.Close()
	if s20, ok := r.(*Session20); ok {
		out.SetPrivAttempts = s20.SetPrivilegeAttempts()
		postAuthTracef(ctx, "set-priv probes=%d", len(out.SetPrivAttempts))
		defer func() { out.CommandProtection = s20.CommandProtectionUsed() }()
	}
	if setup, ok := r.(*OpenBMCSetupSession); ok {
		out.SetPrivAttempts = setup.SetPrivilegeAttempts()
		out.CommandProtection = "setup-cleartext"
		postAuthTracef(ctx, "setup set-priv probes=%d", len(out.SetPrivAttempts))
	}
	errs := make([]string, 0, 5)
	if flow.Mode == "openbmcSetup" {
		setupStart := time.Now()
		setupData, setupErr := collectOpenBMCSetupData(ctx, r)
		out.OpenBMCSetup = setupData
		out.Completed = append(out.Completed, "openbmcSetup")
		if setupErr != nil {
			out.Error = setupErr.Error()
			postAuthTracef(ctx, "openbmc setup local enum failed elapsed=%s err=%v", time.Since(setupStart).Round(time.Millisecond), setupErr)
			return out, setupErr
		}
		postAuthTracef(ctx, "openbmc setup local enum ok elapsed=%s priv=0x%02x payloadStatus=0x%02x providerBlocked=%t", time.Since(setupStart).Round(time.Millisecond), setupData.PrivilegeQueryCC, setupData.PayloadStatusCC, setupData.ProviderBlocked)
		return out, nil
	}
	if flow.Mode == "smcrakpFixedKey" {
		if ctx.Err() != nil {
			postAuthTracef(ctx, "inventory cancelled before smcrakp reads err=%v", ctx.Err())
			return postAuthContextFailure(out, "mcInfo", ctx.Err())
		}
		mcStart := time.Now()
		if info, err := collectMCInfoWithRetry(ctx, r); err == nil {
			out.MCInfo = info
			recordSection(out, "mcInfo", info != nil)
			postAuthTracef(ctx, "smcrakp mc info ok elapsed=%s mfr=%s fw=%s", time.Since(mcStart).Round(time.Millisecond), info.ManufacturerName, info.FirmwareRevision)
		} else {
			postAuthTracef(ctx, "smcrakp mc info failed elapsed=%s err=%v", time.Since(mcStart).Round(time.Millisecond), err)
			markPostAuthIncomplete(out, "mcInfo")
			errs = append(errs, "mc_info: "+err.Error())
		}
		if ctx.Err() != nil {
			postAuthTracef(ctx, "inventory cancelled before smcrakp chassis err=%v", ctx.Err())
			return postAuthContextFailure(out, "chassis", ctx.Err())
		}
		chStart := time.Now()
		if ch, err := collectChassisStatusWithRetry(ctx, r); err == nil {
			out.Chassis = ch
			recordSection(out, "chassis", ch != nil)
			postAuthTracef(ctx, "smcrakp chassis ok elapsed=%s power=%t", time.Since(chStart).Round(time.Millisecond), ch.PowerOn)
		} else {
			postAuthTracef(ctx, "smcrakp chassis failed elapsed=%s err=%v", time.Since(chStart).Round(time.Millisecond), err)
			markPostAuthIncomplete(out, "chassis")
			errs = append(errs, "chassis: "+err.Error())
		}
		if ctx.Err() != nil {
			postAuthTracef(ctx, "inventory cancelled before smcrakp users err=%v", ctx.Err())
			return postAuthContextFailure(out, "users", ctx.Err())
		}
		usersStart := time.Now()
		if users, err := collectUsersWithRetry(ctx, r); err == nil {
			out.Users = users
			recordSection(out, "users", len(users) > 0)
			postAuthTracef(ctx, "smcrakp users ok elapsed=%s count=%d", time.Since(usersStart).Round(time.Millisecond), len(users))
		} else {
			postAuthTracef(ctx, "smcrakp users failed elapsed=%s err=%v", time.Since(usersStart).Round(time.Millisecond), err)
			markPostAuthIncomplete(out, "users")
			errs = append(errs, "users: "+err.Error())
		}
		if ctx.Err() != nil {
			postAuthTracef(ctx, "inventory cancelled before smcrakp lan err=%v", ctx.Err())
			return postAuthContextFailure(out, "lan", ctx.Err())
		}
		lanStart := time.Now()
		if lan, lan6, err := collectLANWithRetry(ctx, r); err == nil {
			out.LAN = lan
			out.LAN6 = lan6
			recordSection(out, "lan", len(lan) > 0)
			recordSection(out, "lan6", len(lan6) > 0)
			postAuthTracef(ctx, "smcrakp lan ok elapsed=%s keys=%d lan6=%d", time.Since(lanStart).Round(time.Millisecond), len(lan), len(lan6))
		} else {
			postAuthTracef(ctx, "smcrakp lan failed elapsed=%s err=%v", time.Since(lanStart).Round(time.Millisecond), err)
			markPostAuthIncomplete(out, "lan")
			errs = append(errs, "lan: "+err.Error())
		}
		fruStart := time.Now()
		fruCtx, fruCancel := postAuthFRUContext(ctx)
		fru, fruErr := collectFRUWithRetry(fruCtx, r, 64)
		fruCancel()
		if fruErr == nil {
			out.FRU = fru
			recordSection(out, "fru", len(fru) > 0)
			postAuthTracef(ctx, "smcrakp fru ok elapsed=%s fields=%d", time.Since(fruStart).Round(time.Millisecond), len(fru))
		} else {
			postAuthTracef(ctx, "smcrakp fru failed elapsed=%s err=%v", time.Since(fruStart).Round(time.Millisecond), fruErr)
			markPostAuthIncomplete(out, "fru")
			errs = append(errs, "fru: "+fruErr.Error())
		}
		if len(errs) > 0 {
			out.Error = strings.Join(errs, "; ")
			postAuthTracef(ctx, "smcrakp partial-error=%s", out.Error)
		}
		if out.MCInfo == nil && out.Chassis == nil && len(out.Users) == 0 && len(out.LAN) == 0 && len(out.LAN6) == 0 && len(out.FRU) == 0 {
			if out.Error == "" {
				out.Error = "smcrakp post-auth inventory unavailable"
			}
			if smcrakpAuthOnlyNoData(errs) {
				postAuthTracef(ctx, "smcrakp auth-only session: command inventory unavailable err=%s", out.Error)
				return out, nil
			}
			postAuthTracef(ctx, "smcrakp inventory failed no-data err=%s", out.Error)
			return out, errors.New(out.Error)
		}
		postAuthTracef(ctx, "smcrakp inventory done mc=%t chassis=%t users=%d lan=%d lan6=%d fru=%d", out.MCInfo != nil, out.Chassis != nil, len(out.Users), len(out.LAN), len(out.LAN6), len(out.FRU))
		return out, nil
	}

	if ctx.Err() != nil {
		postAuthTracef(ctx, "inventory cancelled before mc info err=%v", ctx.Err())
		return postAuthContextFailure(out, "mcInfo", ctx.Err())
	}
	mcStart := time.Now()
	if info, err := collectMCInfoWithRetry(ctx, r); err == nil {
		out.MCInfo = info
		recordSection(out, "mcInfo", info != nil)
		postAuthTracef(ctx, "mc info ok elapsed=%s mfr=%s fw=%s", time.Since(mcStart).Round(time.Millisecond), info.ManufacturerName, info.FirmwareRevision)
	} else {
		postAuthTracef(ctx, "mc info failed elapsed=%s err=%v", time.Since(mcStart).Round(time.Millisecond), err)
		markPostAuthIncomplete(out, "mcInfo")
		errs = append(errs, "mc_info: "+err.Error())
	}
	if ctx.Err() != nil {
		postAuthTracef(ctx, "inventory cancelled before chassis err=%v", ctx.Err())
		return postAuthContextFailure(out, "chassis", ctx.Err())
	}
	chStart := time.Now()
	if ch, err := collectChassisStatusWithRetry(ctx, r); err == nil {
		out.Chassis = ch
		recordSection(out, "chassis", ch != nil)
		postAuthTracef(ctx, "chassis ok elapsed=%s power=%t", time.Since(chStart).Round(time.Millisecond), ch.PowerOn)
	} else {
		postAuthTracef(ctx, "chassis failed elapsed=%s err=%v", time.Since(chStart).Round(time.Millisecond), err)
		markPostAuthIncomplete(out, "chassis")
		errs = append(errs, "chassis: "+err.Error())
	}
	if ctx.Err() != nil {
		postAuthTracef(ctx, "inventory cancelled before users err=%v", ctx.Err())
		return postAuthContextFailure(out, "users", ctx.Err())
	}
	usersStart := time.Now()
	if users, err := collectUsersWithRetry(ctx, r); err == nil {
		out.Users = users
		recordSection(out, "users", len(users) > 0)
		postAuthTracef(ctx, "users ok elapsed=%s count=%d", time.Since(usersStart).Round(time.Millisecond), len(users))
	} else {
		postAuthTracef(ctx, "users failed elapsed=%s err=%v", time.Since(usersStart).Round(time.Millisecond), err)
		markPostAuthIncomplete(out, "users")
		errs = append(errs, "users: "+err.Error())
	}
	if ctx.Err() != nil {
		postAuthTracef(ctx, "inventory cancelled before lan err=%v", ctx.Err())
		return postAuthContextFailure(out, "lan", ctx.Err())
	}
	lanStart := time.Now()
	if lan, lan6, err := collectLANWithRetry(ctx, r); err == nil {
		out.LAN = lan
		out.LAN6 = lan6
		recordSection(out, "lan", len(lan) > 0)
		recordSection(out, "lan6", len(lan6) > 0)
		postAuthTracef(ctx, "lan ok elapsed=%s keys=%d lan6=%d", time.Since(lanStart).Round(time.Millisecond), len(lan), len(lan6))
	} else {
		postAuthTracef(ctx, "lan failed elapsed=%s err=%v", time.Since(lanStart).Round(time.Millisecond), err)
		markPostAuthIncomplete(out, "lan")
		errs = append(errs, "lan: "+err.Error())
	}
	fruStart := time.Now()
	fruCtx, fruCancel := postAuthFRUContext(ctx)
	fru, fruErr := collectFRUWithRetry(fruCtx, r, 64)
	fruCancel()
	if fruErr == nil {
		out.FRU = fru
		recordSection(out, "fru", len(fru) > 0)
		postAuthTracef(ctx, "fru ok elapsed=%s fields=%d", time.Since(fruStart).Round(time.Millisecond), len(fru))
	} else {
		postAuthTracef(ctx, "fru failed elapsed=%s err=%v", time.Since(fruStart).Round(time.Millisecond), fruErr)
		markPostAuthIncomplete(out, "fru")
		errs = append(errs, "fru: "+fruErr.Error())
	}
	if len(errs) > 0 {
		out.Error = strings.Join(errs, "; ")
		postAuthTracef(ctx, "inventory partial-error=%s", out.Error)
	}
	if out.MCInfo == nil && out.Chassis == nil && len(out.Users) == 0 && len(out.LAN) == 0 && len(out.LAN6) == 0 && len(out.FRU) == 0 && len(errs) > 0 {
		out.Error = strings.Join(errs, "; ")
		postAuthTracef(ctx, "inventory failed no-data err=%s", out.Error)
		return out, errors.New(out.Error)
	}
	postAuthTracef(ctx, "inventory done mc=%t chassis=%t users=%d lan=%d lan6=%d fru=%d", out.MCInfo != nil, out.Chassis != nil, len(out.Users), len(out.LAN), len(out.LAN6), len(out.FRU))
	return out, nil
}

func collectOpenBMCSetupData(ctx context.Context, r cmdRunner) (*OpenBMCSetupData, error) {
	out := &OpenBMCSetupData{}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	cc, data, err := r.Exec(NetFnApp, CmdSetSessionPrivilege, []byte{0x00})
	if err != nil {
		out.Error = "privilege query: " + err.Error()
		return out, err
	}
	out.PrivilegeQueryCC = cc
	out.PrivilegeQueryDataHex = hex.EncodeToString(data)

	if err := ctx.Err(); err != nil {
		return out, err
	}
	cc, data, err = r.Exec(NetFnApp, CmdGetPayloadStatus, []byte{0x01})
	if err != nil {
		out.Error = "payload status: " + err.Error()
		return out, err
	}
	out.PayloadStatusCC = cc
	out.PayloadStatusDataHex = hex.EncodeToString(data)

	if err := ctx.Err(); err != nil {
		return out, err
	}
	cc, data, err = r.Exec(NetFnApp, CmdGetPayloadInfo, []byte{0x01, 0x00})
	if err == nil {
		out.PayloadInfoCC = cc
		out.PayloadInfoDataHex = hex.EncodeToString(data)
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}
	cc, data, err = r.Exec(NetFnApp, CmdGetDeviceID, nil)
	if err != nil {
		out.ProviderBlocked = true
		return out, nil
	}
	out.ProviderGetDeviceIDCC = cc
	out.ProviderGetDeviceIDHex = hex.EncodeToString(data)
	out.ProviderBlocked = cc != 0x00 || len(data) == 0
	return out, nil
}

func postAuthContextFailure(out *PostAuthCollection, next string, err error) (*PostAuthCollection, error) {
	markPostAuthIncomplete(out, next)
	wrapped := fmt.Errorf("before %s: %w", next, err)
	out.Error = wrapped.Error()
	return out, wrapped
}

func markPostAuthIncomplete(out *PostAuthCollection, step string) {
	if out.IncompleteAt == "" {
		out.IncompleteAt = step
	}
}

// SessionResourceExhausted reports whether an inventory attempt was refused because the
// BMC had no session slot left: RMCP+ Table 13-15 status 0x01 on the open-session response
// or on RAKP 2/4. Opening more sessions after this only shrinks the pool further, which
// frees only as the BMC ages out sessions already consumed, so the walk has to stop. The
// status byte is matched, not the text: 0x0b decodes to a similar phrase but means the
// requested role was refused. Both err and inv are checked, because a cipher-suite walk
// records the per-suite rejection in CipherMatrix and may return a different last error.
func SessionResourceExhausted(inv *PostAuthCollection, err error) bool {
	if err != nil && sessionResourceRejected(err.Error()) {
		return true
	}
	if inv == nil {
		return false
	}
	if sessionResourceRejected(inv.Error) {
		return true
	}
	for _, a := range inv.CipherMatrix {
		if sessionResourceRejected(a.Error) {
			return true
		}
	}
	return false
}

func sessionResourceRejected(msg string) bool {
	msg = strings.ToLower(msg)
	if !strings.Contains(msg, "status=0x01") {
		return false
	}
	return strings.Contains(msg, "open-session rejected") ||
		strings.Contains(msg, "rakp2 status=") ||
		strings.Contains(msg, "rakp4 status=")
}

// postAuthFRUContext gives the final FRU read a minimum window. FRU runs last and is the
// most command-hungry step (one GetFRUInventoryInfo plus size/16 ReadFRUData per device),
// so it is where the budget runs out. The value is a floor that extends a short deadline,
// not a cap on a longer one.
func postAuthFRUContext(ctx context.Context) (context.Context, context.CancelFunc) {
	const fruFloor = 25 * time.Second
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < fruFloor {
		return context.WithTimeout(context.WithoutCancel(ctx), fruFloor)
	}
	return context.WithCancel(ctx)
}

func effectivePostAuthOpTimeout(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 {
		return 3 * time.Second
	}
	// Keep packet-level waits short so retries can recover within scan budget.
	if scanTimeout < 3*time.Second {
		return scanTimeout
	}
	if scanTimeout > 4*time.Second {
		return 4 * time.Second
	}
	return scanTimeout
}

func collectMCInfoWithRetry(ctx context.Context, r cmdRunner) (*MCInfo, error) {
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := collectMCInfo(ctx, r)
		if err == nil {
			return v, nil
		}
		lastErr = err
		if !isNetTimeoutErr(err) {
			break
		}
	}
	return nil, lastErr
}

func collectChassisStatusWithRetry(ctx context.Context, r cmdRunner) (*ChassisStatus, error) {
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := collectChassisStatus(ctx, r)
		if err == nil {
			return v, nil
		}
		lastErr = err
		if !isNetTimeoutErr(err) {
			break
		}
	}
	return nil, lastErr
}

func collectUsersWithRetry(ctx context.Context, r cmdRunner) ([]UserEntry, error) {
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := collectUsers(ctx, r)
		if err == nil {
			return v, nil
		}
		lastErr = err
		if !isNetTimeoutErr(err) {
			break
		}
	}
	return nil, lastErr
}

func collectLANWithRetry(ctx context.Context, r cmdRunner) (map[string]string, map[string]string, error) {
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		v1, v2, err := collectLAN(ctx, r)
		if err == nil {
			return v1, v2, nil
		}
		lastErr = err
		if !isNetTimeoutErr(err) {
			break
		}
	}
	return nil, nil, lastErr
}

func collectFRUWithRetry(ctx context.Context, r cmdRunner, maxFields int) ([]FRUField, error) {
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := collectFRU(ctx, r, maxFields)
		if err == nil {
			return v, nil
		}
		lastErr = err
		if !isNetTimeoutErr(err) {
			break
		}
	}
	return nil, lastErr
}

func isNetTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func smcrakpAuthOnlyNoData(errs []string) bool {
	if len(errs) == 0 {
		return false
	}
	for _, e := range errs {
		s := strings.ToLower(e)
		if strings.Contains(s, "timeout") || strings.Contains(s, "context deadline exceeded") {
			continue
		}
		return false
	}
	return true
}

func openRunner(host string, port int, flow AuthFlow, timeout time.Duration, prot commandProtection) (cmdRunner, error) {
	switch flow.Version {
	case "2.0":
		if flow.Mode == "openbmcSetup" {
			if strings.TrimSpace(flow.Username) == "" {
				return nil, fmt.Errorf("ipmi 2.0 openbmc setup requires username")
			}
			var lastErr error
			for range 2 {
				s, err := OpenOpenBMCSetupSession(host, port, flow.Username, flow.Suite, timeout)
				if err != nil {
					lastErr = err
					if !isNetTimeoutErr(err) {
						break
					}
					continue
				}
				at, err := s.RequestSessionPrivilege(0x04)
				if err != nil {
					s.Close()
					lastErr = fmt.Errorf("openbmc setup set-session-privilege: %w", err)
					if !isNetTimeoutErr(err) {
						break
					}
					continue
				}
				if !at.Success {
					s.Close()
					return nil, fmt.Errorf("openbmc setup set-session-privilege: cc=0x%02x", at.CC)
				}
				return s, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("ipmi 2.0 openbmc setup session failed")
		}
		if flow.Mode == "openbmcRelabel" {
			if strings.TrimSpace(flow.Username) == "" || strings.TrimSpace(flow.Password) == "" || strings.TrimSpace(flow.RelabelUser) == "" {
				return nil, fmt.Errorf("ipmi 2.0 openbmc relabel requires low-priv credential and relabel user")
			}
			s, err := OpenSession20User(host, port, flow.Username, flow.Password, flow.Suite, timeout)
			if err != nil {
				return nil, err
			}
			s.SetCommandProtection(prot)
			r2, err := s.RelabelActiveSession(flow.RelabelUser, 0x04)
			if err != nil {
				s.Close()
				return nil, fmt.Errorf("openbmc relabel rakp1: %w", err)
			}
			if r2 == nil || r2.ErrorCode != 0 {
				s.Close()
				if r2 != nil {
					return nil, fmt.Errorf("openbmc relabel rakp2 status=0x%02x", r2.ErrorCode)
				}
				return nil, fmt.Errorf("openbmc relabel rakp2 unavailable")
			}
			at, err := s.RequestSessionPrivilege(0x04)
			if err != nil {
				s.Close()
				return nil, fmt.Errorf("openbmc relabel set-session-privilege: %w", err)
			}
			if !at.Success {
				s.Close()
				return nil, fmt.Errorf("openbmc relabel set-session-privilege: cc=0x%02x", at.CC)
			}
			return s, nil
		}
		// OpenBMC default-userKey bypass chained into the RAKP1 active relabel: the bypass
		// alone reaches CALLBACK with no password, then RelabelActiveSession rebinds the
		// active session to an account already confirmed to hold Administrator.
		if flow.Mode == "openbmcBypassRelabel" {
			if len(flow.StaleBMCRand) != 16 || strings.TrimSpace(flow.RelabelUser) == "" {
				return nil, fmt.Errorf("ipmi 2.0 openbmc bypass relabel requires a 16-byte bmcRandomNum and a relabel user")
			}
			s, err := OpenSession20OpenBMCBypass(host, port, flow.Username, flow.StaleBMCRand, flow.Suite, timeout)
			if err != nil {
				return nil, fmt.Errorf("openbmc bypass session: %w", err)
			}
			s.SetCommandProtection(prot)
			r2, err := s.RelabelActiveSession(flow.RelabelUser, 0x04)
			if err != nil {
				s.Close()
				return nil, fmt.Errorf("openbmc bypass relabel rakp1: %w", err)
			}
			if r2 == nil || r2.ErrorCode != 0 {
				s.Close()
				if r2 != nil {
					return nil, fmt.Errorf("openbmc bypass relabel rakp2 status=0x%02x", r2.ErrorCode)
				}
				return nil, fmt.Errorf("openbmc bypass relabel rakp2 unavailable")
			}
			at, err := s.RequestSessionPrivilege(0x04)
			if err != nil {
				s.Close()
				return nil, fmt.Errorf("openbmc bypass relabel set-session-privilege: %w", err)
			}
			if !at.Success {
				s.Close()
				return nil, fmt.Errorf("openbmc bypass relabel set-session-privilege: cc=0x%02x", at.CC)
			}
			return s, nil
		}
		// SMC reserved-role escalation: the reserved role nibble (0x24) in RAKP message 1
		// falls into an ATEN dispatch arm with no default case, copying the slot's existing
		// privilege over the per-user clamp. Message 3 is still signed with our own password,
		// so this needs a real low-privilege credential plus an Administrator account name.
		if flow.Mode == "smcReservedRole" {
			if strings.TrimSpace(flow.Username) == "" || strings.TrimSpace(flow.RelabelUser) == "" {
				return nil, fmt.Errorf("ipmi 2.0 smc reserved-role escalation requires a credential and an admin account name")
			}
			s, err := OpenSession20SMCReservedRole(host, port, flow.Username, flow.Password,
				flow.RelabelUser, SMCReservedRoleByte, timeout)
			if err != nil {
				return nil, fmt.Errorf("smc reserved-role escalation: %w", err)
			}
			s.SetCommandProtection(prot)
			return s, nil
		}
		if flow.Mode == "smcrakpFixedKey" {
			users := smcrakpUserCandidates(flow.Username)
			var lastErr error
			for _, user := range users {
				s, err := OpenSession20WithKey(host, port, user, smcRAKPFixedKey, flow.Suite, timeout)
				if err == nil {
					s.SetCommandProtection(prot)
					return s, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("ipmi 2.0 smcrakp session failed")
		}
		if flow.Mode == "iloRakpNoneBypass" {
			user := strings.TrimSpace(flow.Username)
			if user == "" {
				user = "Administrator"
			}
			var lastErr error
			for range 2 {
				s, err := OpenSession20ILORAKPNone(host, port, user, 0x04, timeout)
				if err == nil {
					s.SetCommandProtection(prot)
					return s, nil
				}
				lastErr = err
				if !isNetTimeoutErr(err) {
					break
				}
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("ipmi 2.0 ilo-rakp-none session failed")
		}
		var lastErr error
		for range 2 {
			var s *Session20
			var err error
			s, err = OpenSession20(host, port, flow.Username, flow.Password, flow.Suite, timeout)
			if err == nil {
				s.SetCommandProtection(prot)
				return s, nil
			}
			lastErr = err
			if !isNetTimeoutErr(err) {
				break
			}
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("ipmi 2.0 session failed")
	case "1.5":
		c, sess, cc, err := login15Conn(host, port, flow.AuthType, flow.Username, flow.Password, timeout)
		if err != nil {
			return nil, err
		}
		if sess == nil {
			if c != nil {
				c.Close()
			}
			return nil, fmt.Errorf("v1.5 login rejected cc=0x%02x", cc)
		}
		// Some BMCs require explicit privilege setup before in-session reads.
		_ = probeCapabilities15(c, sess)
		return &v15Runner{client: c, sess: sess, cmdRetries: 1}, nil
	default:
		return nil, fmt.Errorf("unsupported flow version %q", flow.Version)
	}
}

func smcrakpUserCandidates(primary string) []string {
	primary = strings.TrimSpace(primary)
	if primary != "" {
		return []string{primary}
	}
	return []string{"ADMIN", "admin", ""}
}

func collectMCInfo(ctx context.Context, r cmdRunner) (*MCInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cc, d, err := r.Exec(NetFnApp, CmdGetDeviceID, nil)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 || len(d) < 11 {
		return nil, fmt.Errorf("mc info: cc=0x%02x len=%d", cc, len(d))
	}
	ipmiMaj := d[4] & 0x0f
	ipmiMin := (d[4] >> 4) & 0x0f
	mfr := uint32(d[6]) | uint32(d[7])<<8 | uint32(d[8])<<16
	prod := uint16(d[9]) | uint16(d[10])<<8
	mi := &MCInfo{
		DeviceID:          d[0],
		DeviceRevision:    d[1] & 0x0f,
		FirmwareRevision:  FormatFirmwareRevision(d[2], d[3]),
		IPMIVersion:       fmt.Sprintf("%d.%d", ipmiMaj, ipmiMin),
		ManufacturerID:    mfr,
		ManufacturerName:  ManufacturerNameFor(mfr),
		ProductID:         prod,
		AdditionalSupport: d[5],
	}
	// The auxiliary firmware revision is where vendors carry the third and
	// fourth components of the version they publish; without it the reported
	// value cannot be matched against a vendor advisory (Supermicro 01.07.01
	// arrives here as revision bytes 0x01/0x07 plus aux 0x01).
	if len(d) >= 15 {
		var aux [4]byte
		copy(aux[:], d[11:15])
		mi.AuxFirmwareHex = hex.EncodeToString(aux[:])
		mi.FirmwareRevisionFull = FormatFirmwareRevisionFull(mfr, d[2], d[3], aux)
	}
	return mi, nil
}

func collectUsers(ctx context.Context, r cmdRunner) ([]UserEntry, error) {
	reportCommandProgress(ctx, "user list: discovering slots")
	ch := selectLANChannel(ctx, r)
	cc, d, err := r.Exec(NetFnApp, CmdGetUserAccess, []byte{ch, 0x01})
	if err != nil {
		return nil, err
	}
	if cc != 0x00 || len(d) < 1 {
		return nil, fmt.Errorf("user access bootstrap cc=0x%02x", cc)
	}
	maxUsers := int(d[0] & 0x3f)
	if maxUsers <= 0 {
		maxUsers = 16
	}
	if maxUsers > 16 {
		maxUsers = 16
	}
	out := make([]UserEntry, 0, maxUsers)
	for uid := 1; uid <= maxUsers; uid++ {
		reportCommandProgress(ctx, "user list: slot %d/%d", uid, maxUsers)
		if err := ctx.Err(); err != nil {
			return out, err
		}
		ccA, dA, err := r.Exec(NetFnApp, CmdGetUserAccess, []byte{ch, byte(uid)})
		if err != nil || ccA != 0x00 || len(dA) < 4 {
			continue
		}
		ccN, dN, err := r.Exec(NetFnApp, CmdGetUserName, []byte{byte(uid)})
		name := ""
		if err == nil && ccN == 0x00 && len(dN) > 0 {
			name = sanitizeUserName(dN)
		}
		access := dA[3]
		priv := access & 0x0f
		enabled := (dA[1] & 0x3f) >= byte(uid)
		if !enabled && priv == 0 && !isLikelyRealUserName(name) {
			name = ""
		}
		ue := UserEntry{
			ID:       uid,
			Name:     name,
			Priv:     privName15(priv),
			Enabled:  enabled,
			Callin:   (access & 0x40) == 0,
			LinkAuth: (access & 0x20) != 0,
			IPMIAuth: (access & 0x10) != 0,
			Raw:      hex.EncodeToString(dA),
		}
		out = append(out, ue)
	}
	reportCommandProgress(ctx, "user list: completed %d/%d", len(out), maxUsers)
	return out, nil
}

// collectLAN reads the documented set of Get LAN Configuration Parameters and splits IPv4
// (param < 50) from IPv6 (param >= 50) values. Each parameter is independent, so a single
// unsupported one is normal and must not fail the collection. When every parameter comes
// back empty -- usually the account lacks the privilege this command requires -- it returns
// an error, so the section is not recorded as completed with no data.
func collectLAN(ctx context.Context, r cmdRunner) (map[string]string, map[string]string, error) {
	lan := map[string]string{}
	lan6 := map[string]string{}
	var lastErr error
	var lastCC byte
	ch := selectLANChannel(ctx, r)
	params := map[byte]string{
		0:  "set_in_progress",
		1:  "auth_type_support",
		2:  "auth_type_enable",
		3:  "ip_addr",
		4:  "ip_source",
		5:  "mac",
		6:  "subnet_mask",
		10: "arp_control",
		12: "default_gw_ip",
		13: "default_gw_mac",
		14: "backup_gw_ip",
		15: "backup_gw_mac",
		16: "community_string",
		20: "vlan_id",
		21: "vlan_priority",
		8:  "rmcp_udp_port",
		9:  "rmcp_secondary_port",
		50: "ipv6_support",
		51: "ipv6_ipv4_enables",
		52: "ipv6_header_traffic_class",
		53: "ipv6_header_static_hop_limit",
		54: "ipv6_status",
		55: "ipv6_static_addr_max",
		56: "ipv6_dynamic_addr_max",
		57: "ipv6_dynamic_addr_0",
		58: "ipv6_static_router_1",
	}
	for p, name := range params {
		if err := ctx.Err(); err != nil {
			return lan, lan6, err
		}
		cc, d, err := r.Exec(NetFnTransport, CmdGetLANConfigParams, []byte{ch, p, 0x00, 0x00})
		if err != nil {
			lastErr = err
			continue
		}
		if cc != 0x00 || len(d) < 1 {
			lastCC = cc
			continue
		}
		val := decodeLANParam(p, d[1:])
		if p >= 50 {
			lan6[name] = val
		} else {
			lan[name] = val
		}
		// Preserve the raw byte-array for opaque string fields so downstream
		// consumers can inspect trailing bytes (SNMP community fields are a
		// fixed 18-byte buffer, so trailing NULs and non-UTF8 tails are the
		// norm -- the clean value hides them, the *_raw key records them).
		if p == 16 && len(d) >= 1 {
			raw := d[1:]
			if _, dirty := sanitizeOpaqueString(raw); dirty {
				lan["community_string_raw"] = hex.EncodeToString(raw)
			}
		}
	}
	if len(lan) == 0 && len(lan6) == 0 {
		if lastErr != nil {
			return lan, lan6, fmt.Errorf("lan config params: %w", lastErr)
		}
		return lan, lan6, fmt.Errorf("lan config params: cc=0x%02x", lastCC)
	}
	return lan, lan6, nil
}

func selectLANChannel(ctx context.Context, r cmdRunner) byte {
	const (
		currentChannel = 0x0e
		defaultLAN     = 0x01
	)
	restore := applyFastLANChannelProbe(r)
	defer restore()
	if ctx.Err() != nil {
		return currentChannel
	}
	if cc, d, err := r.Exec(NetFnApp, CmdGetChannelInfo, []byte{currentChannel}); err == nil && cc == 0x00 && len(d) >= 2 {
		if d[1] == 0x04 {
			return d[0] & 0x0f
		}
	}
	if ctx.Err() != nil {
		return currentChannel
	}
	if cc, d, err := r.Exec(NetFnApp, CmdGetChannelInfo, []byte{defaultLAN}); err == nil && cc == 0x00 && len(d) >= 2 {
		if d[1] == 0x04 {
			return d[0] & 0x0f
		}
	}
	return currentChannel
}

func applyFastLANChannelProbe(r cmdRunner) func() {
	if s20, ok := r.(*Session20); ok && s20 != nil && s20.client != nil {
		prevRetries := s20.cmdRetries
		prevTimeout := s20.client.Timeout
		if prevTimeout <= 0 {
			prevTimeout = 5 * time.Second
		}
		shortTimeout := min(prevTimeout, 800*time.Millisecond)
		s20.cmdRetries = 1
		s20.client.Timeout = shortTimeout
		return func() {
			s20.cmdRetries = prevRetries
			s20.client.Timeout = prevTimeout
		}
	}
	if r15, ok := r.(*v15Runner); ok && r15 != nil && r15.client != nil {
		prevTimeout := r15.client.Timeout
		if prevTimeout <= 0 {
			prevTimeout = 5 * time.Second
		}
		shortTimeout := min(prevTimeout, 800*time.Millisecond)
		r15.client.Timeout = shortTimeout
		return func() {
			r15.client.Timeout = prevTimeout
		}
	}
	return func() {}
}

func sanitizeUserName(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	b := append([]byte(nil), raw...)
	for len(b) > 0 {
		last := b[len(b)-1]
		if last == 0x00 || last == 0xff || last == ' ' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	for i, c := range b {
		if c == 0x00 || c == 0xff {
			b = b[:i]
			break
		}
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return ""
	}
	end := 0
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			break
		}
		end = i + 1
	}
	if end == 0 {
		return ""
	}
	return strings.TrimSpace(string(b[:end]))
}

func isLikelyRealUserName(name string) bool {
	if name == "" {
		return false
	}
	return len(name) >= 2
}

// sanitizeOpaqueString normalises a raw byte-array field delivered with a fixed-length
// NUL/garbage pad. It cuts at the first NUL or control byte (0x01..0x1f other than
// TAB/CR/LF, plus 0x7f), then falls back to the printable-ASCII subset if the remainder is
// not valid UTF-8. dirty is true whenever the result is not a byte-for-byte round-trip of
// the input, so a caller can hex-preserve the raw bytes itself (see collectLAN's
// community_string_raw companion key).
func sanitizeOpaqueString(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	dirty := false
	end := len(b)
	for i, c := range b {
		if c == 0x00 || c == 0x7f || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			end = i
			dirty = true
			break
		}
	}
	prefix := b[:end]
	if !utf8.Valid(prefix) {
		clean := make([]byte, 0, len(prefix))
		for _, c := range prefix {
			if c >= 0x20 && c < 0x7f {
				clean = append(clean, c)
			}
		}
		return string(clean), true
	}
	return string(prefix), dirty
}

func decodeLANParam(param byte, d []byte) string {
	switch param {
	case 0:
		if len(d) >= 1 {
			switch d[0] {
			case 0:
				return "set-complete"
			case 1:
				return "set-in-progress"
			case 2:
				return "commit-write"
			default:
				return fmt.Sprintf("0x%02x", d[0])
			}
		}
	case 1, 2:
		if len(d) >= 1 {
			return decodeAuthMask(d[0])
		}
	case 3:
		if len(d) >= 4 {
			return fmt.Sprintf("%d.%d.%d.%d", d[0], d[1], d[2], d[3])
		}
	case 4:
		if len(d) >= 1 {
			// IP address source is bits[3:0]; bits[7:4] are reserved. Some BMCs
			// leave the reserved nibble set (e.g. 0xf1), so mask before decoding or
			// a static/DHCP source is misreported as a raw "0xf1".
			switch d[0] & 0x0f {
			case 0:
				return "unspecified"
			case 1:
				return "static"
			case 2:
				return "dhcp"
			case 3:
				return "bios"
			case 4:
				return "other"
			default:
				return fmt.Sprintf("0x%02x", d[0]&0x0f)
			}
		}
	case 6, 12, 14:
		if len(d) >= 4 {
			return fmt.Sprintf("%d.%d.%d.%d", d[0], d[1], d[2], d[3])
		}
	case 5, 13:
		if len(d) >= 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5])
		}
	case 10:
		if len(d) >= 1 {
			return fmt.Sprintf("0x%02x", d[0])
		}
	case 15:
		if len(d) >= 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5])
		}
	case 16:
		if len(d) > 0 {
			s, _ := sanitizeOpaqueString(d)
			return s
		}
	case 20:
		if len(d) >= 2 {
			v := binary.LittleEndian.Uint16(d[:2])
			return fmt.Sprintf("%d", v&0x0fff)
		}
	case 21:
		if len(d) >= 1 {
			return fmt.Sprintf("%d", d[0]&0x07)
		}
	case 8, 9:
		if len(d) >= 2 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint16(d[:2]))
		}
	case 50:
		if len(d) >= 1 {
			return fmt.Sprintf("0x%02x", d[0])
		}
	case 51:
		if len(d) >= 1 {
			return fmt.Sprintf("0x%02x", d[0])
		}
	case 52, 53, 54, 55, 56:
		if len(d) >= 1 {
			return fmt.Sprintf("0x%02x", d[0])
		}
	case 57:
		if len(d) >= 17 {
			return decodeIPv6(d[1:17])
		}
	case 58:
		if len(d) >= 16 {
			return decodeIPv6(d[:16])
		}
	}
	return hex.EncodeToString(d)
}

func decodeAuthMask(v byte) string {
	var out []string
	if v&0x01 != 0 {
		out = append(out, "none")
	}
	if v&0x02 != 0 {
		out = append(out, "md2")
	}
	if v&0x04 != 0 {
		out = append(out, "md5")
	}
	if v&0x10 != 0 {
		out = append(out, "password")
	}
	if len(out) == 0 {
		return fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(out, ",")
}

func decodeIPv6(b []byte) string {
	if len(b) < 16 {
		return hex.EncodeToString(b)
	}
	parts := make([]string, 8)
	for i := range 8 {
		parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(b[i*2:i*2+2]))
	}
	return strings.Join(parts, ":")
}

func collectChassisStatus(ctx context.Context, r cmdRunner) (*ChassisStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cc, d, err := r.Exec(NetFnChassis, CmdGetChassisStatus, nil)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 || len(d) < 3 {
		return nil, fmt.Errorf("chassis status: cc=0x%02x len=%d", cc, len(d))
	}
	cs := &ChassisStatus{
		PowerOn:           (d[0] & 0x01) != 0,
		PowerOverload:     (d[0] & 0x02) != 0,
		PowerInterlock:    (d[0] & 0x04) != 0,
		MainPowerFault:    (d[0] & 0x08) != 0,
		PowerControlFault: (d[0] & 0x10) != 0,
		IdentifyOn:        (d[2] & 0x40) != 0,
		CoolingFault:      (d[2] & 0x08) != 0,
		DriveFault:        (d[2] & 0x04) != 0,
		Raw:               hex.EncodeToString(d),
	}
	cs.PowerRestore = chassisPowerRestore((d[0] >> 5) & 0x03)
	cs.LastEvent = chassisLastEvent(d[1])
	return cs, nil
}

func chassisPowerRestore(v byte) string {
	switch v {
	case 0x0:
		return "always-off"
	case 0x1:
		return "restore"
	case 0x2:
		return "always-on"
	default:
		return fmt.Sprintf("0x%02x", v)
	}
}

func chassisLastEvent(v byte) string {
	if v == 0 {
		return "none"
	}
	var out []string
	if v&0x01 != 0 {
		out = append(out, "ac-failed")
	}
	if v&0x02 != 0 {
		out = append(out, "overload")
	}
	if v&0x04 != 0 {
		out = append(out, "interlock")
	}
	if v&0x08 != 0 {
		out = append(out, "power-fault")
	}
	if v&0x10 != 0 {
		out = append(out, "power-command")
	}
	if len(out) == 0 {
		return fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(out, ",")
}

const (
	// fruMaxConsecutiveMisses stops the FRU device walk once this many consecutive IDs
	// fail or report unsupported. FRU devices are allocated from 0 up, so a run of
	// misses means there is nothing further to find.
	fruMaxConsecutiveMisses = 3
	// fruMaxDeviceID caps how far the walk goes even when devices keep answering.
	// Baseboard plus a handful of DIMM/PSU/backplane FRUs is the realistic shape.
	fruMaxDeviceID = 15
)

func collectFRU(ctx context.Context, r cmdRunner, maxFields int) ([]FRUField, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxFields <= 0 {
		return nil, nil
	}
	out := make([]FRUField, 0, maxFields)
	seen := map[string]struct{}{}
	// The device walk is bounded. Walking deviceID 0..255 and stopping only on maxFields
	// blind-probes all 256 ids when device 0 yields few fields, each costing a round trip
	// and, on a non-answering BMC, a full op timeout -- enough to consume the whole
	// post-auth budget before FRU lands. Real systems expose the baseboard at device 0
	// plus a few others, so probe 0 always and continue only while devices answer.
	misses := 0
	for deviceID := 0; deviceID <= 255 && len(out) < maxFields; deviceID++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if deviceID > 0 && (misses >= fruMaxConsecutiveMisses || deviceID > fruMaxDeviceID) {
			break
		}
		buf, supported, err := readFRUDevice(ctx, r, byte(deviceID))
		if err != nil {
			if deviceID == 0 {
				return nil, err
			}
			misses++
			continue
		}
		if !supported || len(buf) == 0 {
			misses++
			continue
		}
		misses = 0
		fields := parseFRUFields(buf, maxFields-len(out), deviceID)
		for _, f := range fields {
			key := fmt.Sprintf("%d|%s|%d|%s", f.DeviceID, f.Area, f.Index, f.Value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, f)
			if len(out) >= maxFields {
				break
			}
		}
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func collectFRUDevice(ctx context.Context, r cmdRunner, deviceID byte, maxFields int) ([]FRUField, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxFields <= 0 {
		return nil, nil
	}
	buf, supported, err := readFRUDevice(ctx, r, deviceID)
	if err != nil {
		return nil, err
	}
	if !supported || len(buf) == 0 {
		return nil, nil
	}
	return parseFRUFields(buf, maxFields, int(deviceID)), nil
}

func readFRUDevice(ctx context.Context, r cmdRunner, deviceID byte) ([]byte, bool, error) {
	cc, d, err := r.Exec(NetFnStorage, CmdGetFRUInventoryInfo, []byte{deviceID})
	if err != nil {
		return nil, false, err
	}
	if cc == 0xc1 || cc == 0xcb || cc == 0xcc {
		return nil, false, nil
	}
	if cc != 0x00 || len(d) < 3 {
		return nil, true, fmt.Errorf("fru info device=%d cc=0x%02x", deviceID, cc)
	}
	size := int(binary.LittleEndian.Uint16(d[:2]))
	if size <= 0 {
		return nil, true, nil
	}
	if (d[2] & 0x01) != 0 {
		size *= 2 // size in words
	}
	if size > 2048 {
		size = 2048
	}
	buf := make([]byte, 0, size)
	off := 0
	for off < size {
		if err := ctx.Err(); err != nil {
			return nil, true, err
		}
		cnt := min(size-off, 16)
		req := []byte{deviceID, byte(off & 0xff), byte((off >> 8) & 0xff), byte(cnt)}
		ccR, dR, err := r.Exec(NetFnStorage, CmdReadFRUData, req)
		if err != nil {
			return nil, true, err
		}
		if ccR != 0x00 || len(dR) < 1 {
			break
		}
		n := int(dR[0])
		if n <= 0 || len(dR) < 1+n {
			break
		}
		buf = append(buf, dR[1:1+n]...)
		off += n
	}
	return buf, true, nil
}

func parseFRUFields(raw []byte, max int, deviceID int) []FRUField {
	if len(raw) < 8 || max <= 0 {
		return nil
	}
	areas := []struct {
		name  string
		off   int
		start int
	}{
		{"chassis", int(raw[2]) * 8, 3},
		{"board", int(raw[3]) * 8, 6},
		{"product", int(raw[4]) * 8, 3},
	}
	out := make([]FRUField, 0, max)
	if raw[2] != 0 {
		chassisOff := int(raw[2]) * 8
		if chassisOff+3 <= len(raw) {
			if name := fruChassisTypeName(raw[chassisOff+2]); name != "" {
				out = append(out, FRUField{DeviceID: deviceID, Area: "chassis", Index: -1, Name: "Chassis Type", Value: name})
			}
		}
	}
	if raw[3] != 0 {
		boardOff := int(raw[3]) * 8
		if boardOff+6 <= len(raw) {
			if date := decodeFRUMfgDate(raw[boardOff+3 : boardOff+6]); date != "" {
				out = append(out, FRUField{DeviceID: deviceID, Area: "board", Index: -1, Name: "Board Mfg Date", Value: date})
			}
		}
	}
	for _, a := range areas {
		if a.off <= 0 || a.off+2 > len(raw) {
			continue
		}
		ln := int(raw[a.off+1]) * 8
		if ln <= 0 || a.off+ln > len(raw) {
			continue
		}
		area := raw[a.off : a.off+ln]
		idx := 0
		for i := a.start; i < len(area) && len(out) < max; {
			t := area[i]
			i++
			if t == 0xc1 {
				break
			}
			l := int(t & 0x3f)
			enc := t >> 6
			if l == 0 {
				idx++
				continue
			}
			if i+l > len(area) {
				break
			}
			f := area[i : i+l]
			i += l
			// A present field always advances the positional index, even if it
			// decodes to empty (all-spaces pad, leading-NUL). Skipping idx++ here
			// desynced every later field in the area, mislabeling it (e.g. the
			// Serial emitted under the Version name).
			if val := decodeFRUField(enc, f); val != "" {
				out = append(out, FRUField{DeviceID: deviceID, Area: a.name, Index: idx, Name: fruFieldName(a.name, idx), Value: val})
			}
			idx++
		}
	}
	return out
}

func decodeFRUMfgDate(b []byte) string {
	if len(b) < 3 {
		return ""
	}
	mins := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if mins == 0 {
		return ""
	}
	base := time.Date(1996, time.January, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(mins) * time.Minute).In(time.Local).Format("Mon Jan _2 15:04:05 2006 MST")
}

func fruChassisTypeName(v byte) string {
	switch v {
	case 0x01:
		return "Other"
	case 0x02:
		return "Unknown"
	case 0x03:
		return "Desktop"
	case 0x04:
		return "Low Profile Desktop"
	case 0x05:
		return "Pizza Box"
	case 0x06:
		return "Mini Tower"
	case 0x07:
		return "Tower"
	case 0x08:
		return "Portable"
	case 0x09:
		return "Laptop"
	case 0x0a:
		return "Notebook"
	case 0x0b:
		return "Hand Held"
	case 0x0c:
		return "Docking Station"
	case 0x0d:
		return "All in One"
	case 0x0e:
		return "Sub Notebook"
	case 0x0f:
		return "Space-saving"
	case 0x10:
		return "Lunch Box"
	case 0x11:
		return "Main Server Chassis"
	case 0x12:
		return "Expansion Chassis"
	case 0x13:
		return "SubChassis"
	case 0x14:
		return "Bus Expansion Chassis"
	case 0x15:
		return "Peripheral Chassis"
	case 0x16:
		return "RAID Chassis"
	case 0x17:
		return "Rack Mount Chassis"
	case 0x18:
		return "Sealed-case PC"
	case 0x19:
		return "Multi-system Chassis"
	case 0x1a:
		return "CompactPCI"
	case 0x1b:
		return "AdvancedTCA"
	case 0x1c:
		return "Blade"
	case 0x1d:
		return "Blade Enclosure"
	default:
		return fmt.Sprintf("0x%02x", v)
	}
}

func fruFieldName(area string, idx int) string {
	switch area {
	case "chassis":
		switch idx {
		case 0:
			return "Chassis Part Number"
		case 1:
			return "Chassis Serial"
		}
	case "board":
		switch idx {
		case 0:
			return "Board Mfg"
		case 1:
			return "Board Product"
		case 2:
			return "Board Serial"
		case 3:
			return "Board Part Number"
		case 4:
			return "Board FRU File ID"
		}
	case "product":
		switch idx {
		case 0:
			return "Product Manufacturer"
		case 1:
			return "Product Name"
		case 2:
			return "Product Part Number"
		case 3:
			return "Product Version"
		case 4:
			return "Product Serial"
		case 5:
			return "Product Asset Tag"
		case 6:
			return "Product FRU File ID"
		}
	}
	return fmt.Sprintf("%s %d", fruAreaLabel(area), idx)
}

func fruAreaLabel(area string) string {
	switch area {
	case "chassis":
		return "Chassis"
	case "board":
		return "Board"
	case "product":
		return "Product"
	default:
		if area == "" {
			return "FRU"
		}
		return strings.ToUpper(area[:1]) + area[1:]
	}
}

// decodeFRUField decodes a FRU type/length string per the IPMI Platform Mgmt FRU
// spec: bits[7:6] select the encoding -- 0b11 8-bit ASCII, 0b10 6-bit packed
// ASCII, 0b01 BCD-plus, 0b00 raw binary.
func decodeFRUField(enc byte, b []byte) string {
	switch enc {
	case 0x3: // 8-bit ASCII / language-dependent
		s, _ := sanitizeOpaqueString(b)
		return strings.TrimSpace(s)
	case 0x2: // 6-bit packed ASCII: LSB-first 6-bit groups, char = value + 0x20
		var sb strings.Builder
		var acc uint
		var nbits uint
		for _, by := range b {
			acc |= uint(by) << nbits
			nbits += 8
			for nbits >= 6 {
				sb.WriteByte(byte(acc&0x3f) + 0x20)
				acc >>= 6
				nbits -= 6
			}
		}
		return strings.TrimRight(sb.String(), " ")
	case 0x1: // BCD plus: two nibbles/byte, 0-9 digits, 0xA space, 0xB '-', 0xC '.'
		var sb strings.Builder
		for _, by := range b {
			for _, nib := range [2]byte{by >> 4, by & 0x0f} {
				switch {
				case nib <= 9:
					sb.WriteByte('0' + nib)
				case nib == 0xa:
					sb.WriteByte(' ')
				case nib == 0xb:
					sb.WriteByte('-')
				case nib == 0xc:
					sb.WriteByte('.')
				}
			}
		}
		return strings.TrimSpace(sb.String())
	default: // 0b00 raw binary
		return hex.EncodeToString(b)
	}
}

func privName15(p byte) string {
	switch p & 0x0f {
	case 0x01:
		return "callback"
	case 0x02:
		return "user"
	case 0x03:
		return "operator"
	case 0x04:
		return "admin"
	case 0x05:
		return "oem"
	default:
		return fmt.Sprintf("0x%02x", p)
	}
}
