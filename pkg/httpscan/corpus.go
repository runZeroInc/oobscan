// Package httpscan sweeps firmware-derived HTTP endpoints against BMCs and
// related OOB devices. The endpoint list stays grounded in firmware artifacts.
package httpscan

import (
	"slices"
	"sort"
)

// MatchType describes whether an endpoint is an exact URL path or a dynamic
// handler prefix that should still respond meaningfully at the prefix root.
type MatchType string

const (
	MatchExact  MatchType = "exact"
	MatchPrefix MatchType = "prefix"
)

// Endpoint is one firmware-derived HTTP target.
type Endpoint struct {
	Vendor  string
	Product string
	Path    string
	Match   MatchType
	Tags    []string
	Source  string
	Notes   string
}

// Corpus lists the exact files and handler roots worth probing pre-auth.
// Items are grouped only for readability; AggregatedTargets() deduplicates by
// path so shared surfaces such as /redfish/v1/ probe once per host.
var Corpus = []Endpoint{
	// ASRock Rack / AMI MegaRAC-SP, derived from firmware analysis.
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/api/", Match: MatchPrefix, Tags: []string{"dynamic", "rest"}, Source: "firmware-analysis", Notes: "lighttpd FastCGI spx_restservice root"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/ext/", Match: MatchPrefix, Tags: []string{"dynamic", "rest"}, Source: "firmware-analysis", Notes: "lighttpd FastCGI spx_restservice_ext root"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/redfish/", Match: MatchPrefix, Tags: []string{"dynamic", "redfish"}, Source: "firmware-analysis"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis", Notes: "pre-auth Redfish root"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/wsman", Match: MatchPrefix, Tags: []string{"dynamic", "wsman"}, Source: "firmware-analysis"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/Java/", Match: MatchPrefix, Tags: []string{"static", "ikvm"}, Source: "firmware-analysis"},

	// Fujitsu iRMC, derived from firmware analysis.
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/", Match: MatchPrefix, Tags: []string{"dynamic", "rpc"}, Source: "firmware-analysis", Notes: "large ASP RPC surface"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getsysinfo.asp", Match: MatchExact, Tags: []string{"info", "rpc"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getsessioninfo.asp", Match: MatchExact, Tags: []string{"info", "rpc", "session"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getactivelancfg.asp", Match: MatchExact, Tags: []string{"info", "rpc", "config"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getalluserinfo.asp", Match: MatchExact, Tags: []string{"info", "rpc", "users"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getallservicescfg.asp", Match: MatchExact, Tags: []string{"info", "rpc", "config"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getdatetime.asp", Match: MatchExact, Tags: []string{"info", "rpc"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/hoststatus.asp", Match: MatchExact, Tags: []string{"info", "rpc"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/configurepef.asp", Match: MatchExact, Tags: []string{"dynamic", "rpc", "config"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/generatessl.asp", Match: MatchExact, Tags: []string{"dynamic", "rpc", "admin"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/flashfile_upload_starts.asp", Match: MatchExact, Tags: []string{"dynamic", "rpc", "upload"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/dwldfwimg.asp", Match: MatchExact, Tags: []string{"dynamic", "rpc", "upload"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/setldapcfg.asp", Match: MatchExact, Tags: []string{"dynamic", "rpc", "config"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/index.html", Match: MatchExact, Tags: []string{"static", "info"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/iRMCVersionInfo.txt", Match: MatchExact, Tags: []string{"static", "info", "version"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/config/bmc.cfg", Match: MatchExact, Tags: []string{"static", "config"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/Disclaimer.txt.gz", Match: MatchExact, Tags: []string{"static", "docs"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/autocall_en.pdf", Match: MatchExact, Tags: []string{"static", "docs"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/ThirdPartyLicenseReadme.squashfs", Match: MatchExact, Tags: []string{"static", "fingerprint", "archive"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/Report.xsd", Match: MatchExact, Tags: []string{"static", "schema"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/Report.xslt", Match: MatchExact, Tags: []string{"static", "schema"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/SVbrand.jpg", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/ServerView.gif", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},

	// APC / Schneider NMC3 (hw21, AP964x), derived from firmware analysis. Only
	// Read-only pre-auth pages are listed (no /Forms/login1 or /Forms/macontrol1 -
	// POSTing to those would trip the bad-login counter / PCNS handshake). The
	// auth gate (FUN_1049509e) whitelists /logon.htm, /limstat.htm, /macontrol.htm
	// and static assets; everything else redirects to /logon.htm.
	{Vendor: "apc", Product: "NMC3", Path: "/logon.htm", Match: MatchExact, Tags: []string{"static", "info", "fingerprint", "login"}, Source: "firmware-analysis", Notes: "NMC3 form-login page; identifies APC + serves device name pre-auth"},
	{Vendor: "apc", Product: "NMC3", Path: "/limstat.htm", Match: MatchExact, Tags: []string{"info", "config", "fingerprint"}, Source: "firmware-analysis", Notes: "Limited Status Page: serves device/UPS status pre-auth when enabled (web -lsp)"},
	{Vendor: "apc", Product: "NMC3", Path: "/macontrol.htm", Match: MatchExact, Tags: []string{"info", "fingerprint"}, Source: "firmware-analysis", Notes: "PowerChute/PCNS control page; no-auth whitelisted (web-session bypass, PCNS-handshake gated)"},
	{Vendor: "apc", Product: "NMC3", Path: "/config.ini", Match: MatchExact, Tags: []string{"config", "fingerprint"}, Source: "firmware-analysis", Notes: "full device config export (auth-gated); presence fingerprints APC NMC"},
	{Vendor: "apc", Product: "NMC3", Path: "/gz_seui.js", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis", Notes: "no-auth whitelisted NMC3 web-framework JS; APC fingerprint"},

	// Supermicro / ATEN, derived from firmware analysis.
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/", Match: MatchPrefix, Tags: []string{"dynamic", "cgi"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi-bin/", Match: MatchPrefix, Tags: []string{"dynamic", "cgi"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/login.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "login"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/login_oem.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "login"}, Source: "firmware-analysis", Notes: "POST login handler, not a pre-auth info leak: GET returns 404, POST needs a body (411). Verified live on X10/X11/H13 2026-07-29. Do not re-tag 'info'."},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/logout.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "session"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/url_redirect.cgi", Match: MatchExact, Tags: []string{"info", "cgi", "redirect"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/rakp_ctrl.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "ipmi"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/redfish_launch_ikvm.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "ikvm"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/upload_ssl.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/firmware_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/bios_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/oem_firmware_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/cpld_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/ec_upload.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "upload"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/config_user.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config", "users"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/config_tftpd.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/config_alert.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/system_event_log.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "logs"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/clear_log.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "logs", "admin"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/save_IPMI_config.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/load_IPMI_factory_config.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config", "admin"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/load_IPMI_preserve_config.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "config", "admin"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/uid_ctrl.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "hardware"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/op.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/ipmi.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "ipmi"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/JsonSchemas.tar.xz", Match: MatchExact, Tags: []string{"static", "schema", "redfish"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/Metadata.tar.xz", Match: MatchExact, Tags: []string{"static", "metadata", "redfish"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/Snapshot.bmp", Match: MatchExact, Tags: []string{"static", "snapshot"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/maintenance.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/config_ssl.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/servh_power.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/main_cpld_check_version.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/main_ipreset.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/topmenu.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/config_ip_ctrl.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/page/main_trouble_shooting.www", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis"},
	// Login HTML (served pre-auth via the index redirect). Its JS stack fingerprints
	// the generation: coreui/kendo + jquery-3 ("Supermicro BMC Login") = X11+, vs
	// the legacy prototype.js/YUI login with an empty <title> = X10. FingerprintBody
	// tags this as "smc-ui:coreui" / "smc-ui:legacy" (see httpscan.fingerprintText).
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/cgi/url_redirect.cgi?url_name=login", Match: MatchExact, Tags: []string{"static", "fingerprint", "login"}, Source: "firmware-analysis", Notes: "login page; coreui vs legacy JS stack splits X11+ from X10"},
	// Static Redfish version file present on the coreui generations (X11/X12/X13/H13),
	// absent on X10 and X14/bmcweb. Serves a bare version string (e.g. "1.21.1").
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/rf_version", Match: MatchExact, Tags: []string{"static", "info", "fingerprint", "version"}, Source: "firmware-analysis", Notes: "coreui-era static Redfish version marker"},

	// OpenBMC, derived from firmware analysis.
	{Vendor: "openbmc", Product: "phosphor", Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis"},

	// Known high-signal unauth vendor endpoints already covered elsewhere in oobscan.
	{Vendor: "hpe", Product: "iLO", Path: "/xmldata?item=all", Match: MatchExact, Tags: []string{"info", "xml", "legacy"}, Source: "pkg/ilo/xmldata.go", Notes: "public pre-auth iLO inventory endpoint"},
	{Vendor: "dell", Product: "iDRAC", Path: "/data?get=fwVersion", Match: MatchExact, Tags: []string{"info", "xml", "legacy"}, Source: "pkg/idrac/idrac.go"},
	{Vendor: "dell", Product: "iDRAC", Path: "/data/login", Match: MatchExact, Tags: []string{"info", "xml", "login"}, Source: "pkg/idrac/idrac.go"},
	{Vendor: "dell", Product: "iDRAC", Path: "/cgi-bin/login", Match: MatchExact, Tags: []string{"dynamic", "cgi", "login"}, Source: "pkg/idrac/idrac.go"},
	{Vendor: "dell", Product: "iDRAC", Path: "/sysmgmt/2015/bmc/info", Match: MatchExact, Tags: []string{"info", "rest"}, Source: "pkg/idrac/idrac.go"},
	{Vendor: "dell", Product: "iDRAC", Path: "/redfish/v1/Managers/iDRAC.Embedded.1", Match: MatchExact, Tags: []string{"info", "redfish"}, Source: "pkg/idrac/idrac.go"},
	{Vendor: "dell", Product: "iDRAC", Path: "/vkvm/", Match: MatchPrefix, Tags: []string{"info", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: "AVOCENT avct KVM WebSocket endpoint (wss://host/vkvm/) present on iDRAC7-10; reachability fingerprint of the screen-share channel (raw RFB is on TCP/5900, caught by kvm.vnc)"},

	// --- 2026 "Lights Out" additions (per-vendor investigation reports in
	// internal analysis). ---
	// HPE iLO unauth UPnP/SSDP device descriptor: model / serial / UUID pre-auth.
	{Vendor: "hpe", Product: "iLO", Path: "/upnp/BasicDevice.xml", Match: MatchExact, Tags: []string{"info", "xml", "static", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth UPnP descriptor: manufacturer/model/serial/UUID"},
	// Fujitsu iRMC SCCI unauth identity leak (EmitHpSimInfo), default-ON S5+S6.
	{Vendor: "fujitsu", Product: "iRMC", Path: "/nwsi/", Match: MatchPrefix, Tags: []string{"dynamic", "rpc", "info"}, Source: "firmware-analysis", Notes: "SCCI HP-SIM unauth XML identity leak"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis", Notes: "pre-auth Redfish service root"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/rpc/getallconfigs.asp", Match: MatchExact, Tags: []string{"info", "rpc", "config"}, Source: "firmware-analysis", Notes: "bulk config path; test sessionless"},
	// AMI MegaRAC / ASRock sensitive spx_restservice routes (CVE-2022-40259 family):
	// probe sessionless to spot unauthorized authorized-route mis-tagging.
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/api/maintenance/firmware/flash-progress", Match: MatchExact, Tags: []string{"dynamic", "rest", "admin"}, Source: "firmware-analysis"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/api/maintenance/restore_defaults", Match: MatchExact, Tags: []string{"dynamic", "rest", "admin"}, Source: "firmware-analysis"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/api/settings/users", Match: MatchExact, Tags: []string{"dynamic", "rest", "users"}, Source: "firmware-analysis"},
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/api/asrr/maintenance/BMC/flash-progress", Match: MatchExact, Tags: []string{"dynamic", "rest", "admin"}, Source: "firmware-analysis"},

	// Lenovo XClarity Controller (XCC/XCC2), derived from
	// firmware analysis. The Redfish
	// access gate (Access.lua/AuthenticationHelper) permits exactly the no-auth
	// set below; the gunicorn web-GUI app additionally exposes several
	// unauthenticated /api/providers/* and /nonauth/* endpoints (info disclosure
	// + a replayable login nonce + Edge route/token mechanics; state change is
	// not established).
	{Vendor: "lenovo", Product: "XCC", Path: "/DeviceDescription.json", Match: MatchExact, Tags: []string{"info", "json", "static", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth device descriptor (dedicated nginx location) -- highest-value XCC pre-auth fingerprint"},
	{Vendor: "lenovo", Product: "XCC", Path: "/redfish/v1", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis", Notes: "pre-auth Redfish service root (isPublicResource allowlist)"},
	{Vendor: "lenovo", Product: "XCC", Path: "/redfish/v1/openapi.yaml", Match: MatchExact, Tags: []string{"info", "redfish", "static", "recon"}, Source: "firmware-analysis", Notes: "pre-auth 4.3MB OpenAPI map of the full Redfish surface"},
	{Vendor: "lenovo", Product: "XCC", Path: "/redfish/v1/$metadata", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis", Notes: "pre-auth OData metadata"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/get_nonce", Match: MatchExact, Tags: []string{"dynamic", "api", "session"}, Source: "firmware-analysis", Notes: "unauth: returns replayable uuid5 login nonce (weak anti-automation quirk)"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/logoninfo", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth: serial number + machine type"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/xccenvinfo", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth: platform/family/codename"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/imm_active_events", Match: MatchExact, Tags: []string{"info", "api"}, Source: "firmware-analysis", Notes: "unauth: active event-log entries"},
	{Vendor: "lenovo", Product: "XCC", Path: "/nonauth/dataset/virtual-lcd", Match: MatchExact, Tags: []string{"info", "api"}, Source: "firmware-analysis", Notes: "unauth: temperatures / power / events"},
	{Vendor: "lenovo", Product: "XCC", Path: "/nonauth", Match: MatchPrefix, Tags: []string{"dynamic", "api"}, Source: "firmware-analysis", Notes: "web-GUI proxy prefix; Edge routes live here, but token acceptance and state change are unproven"},

	// --- KVM / virtual-media / virtual-USB surfaces. These are the
	// firmware-derived HTTP surfaces that either fingerprint the remote-console
	// stack or, on the applet launchers, hand the viewer its redirection session
	// token in the JNLP/launch args (a token that on several stacks is replayable
	// and not source-IP-pinned). The redirection data channels themselves are
	// non-HTTP ports probed by pkg/check kvm_check.go.
	// Supermicro/ATEN iKVM: redfish_launch_ikvm.cgi + url_redirect.cgi already
	// covered above; add the applet JNLP.
	{Vendor: "supermicro", Product: "ATEN IPMI", Path: "/Java/jviewer.jnlp", Match: MatchExact, Tags: []string{"info", "ikvm", "jnlp", "session"}, Source: "firmware-analysis", Notes: "ATEN iKVM JNLP (main-class tw.com.aten.ikvm.KVMMain); token-as-KVM-password model, older builds embed it in args"},
	// AMI MegaRAC JViewer - ASRock/TYAN/Gigabyte and Fujitsu iRMC (SP-X 13.x) all
	// serve the same com.ami.kvm.jviewer applet; the JNLP args carry -kvmtoken.
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/Java/jviewer.jnlp", Match: MatchExact, Tags: []string{"info", "ikvm", "jnlp", "session"}, Source: "firmware-analysis", Notes: "AMI JViewer JNLP; -kvmtoken/-webcookie args validate on adviserd:7578 + cd/hd/fdserverapp:5120-5123 (128-byte urandom token, NOT IP-pinned = replayable until expiry)"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/Java/jviewer.jnlp", Match: MatchExact, Tags: []string{"info", "ikvm", "jnlp", "session"}, Source: "firmware-analysis", Notes: "Fujitsu iRMC = AMI SP-X JViewer; vendor tag 'American Megatrends' despite Fujitsu skin"},
	{Vendor: "fujitsu", Product: "iRMC", Path: "/Java/release/JViewer.jar", Match: MatchExact, Tags: []string{"static", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: "com.ami.kvm.jviewer.JViewer - proves AMI SP-X lineage under the Fujitsu brand"},
	// HPE iLO Integrated Remote Console launchers (.NET ClickOnce / JNLP / HTML5).
	{Vendor: "hpe", Product: "iLO", Path: "/html/IRC.application", Match: MatchExact, Tags: []string{"info", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: ".NET ClickOnce IRC manifest (constant publicKeyToken 6037708d28143739); trustURLParameters=true => sessionKey travels in the launch URL"},
	{Vendor: "hpe", Product: "iLO", Path: "/html5/index.html", Match: MatchExact, Tags: []string{"info", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: "iLO HTML5 remote console entry (WebSocket console/vmedia over 443)"},
	// Cisco CIMC HTML5 vKVM.
	{Vendor: "cisco", Product: "CIMC", Path: "/kvm/gimme_dat_port", Match: MatchExact, Tags: []string{"info", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: "HTML5 client port lookup, returns {\"kvm_port\":N}; test sessionless -- discloses the kvmd port"},
	{Vendor: "cisco", Product: "CIMC", Path: "/kvm/kvm.html", Match: MatchExact, Tags: []string{"static", "ikvm", "fingerprint"}, Source: "firmware-analysis", Notes: "HTML5 vKVM UI (<title>vKVM</title>, <kvm-ui>); data channel is kvmd TCP/2068, WS subprotocol cisco-kvm-protocol"},

	// --- Modern IP-KVM appliances.
	// These are ClassKVM devices, not BMCs; the endpoints below are the
	// unauthenticated info/version surfaces that fingerprint the stack and leak
	// firmware version or no-auth posture. Probed pre-auth with GETs; the
	// destructive CVEs (ES3 /upload file-write, NanoKVM /api/network/wifi) are
	// catalogued separately and not exercised here.
	{Vendor: "jetkvm", Product: "JetKVM", Path: "/device/ui-config.js", Match: MatchExact, Tags: []string{"info", "static", "fingerprint", "version"}, Source: "eclypsium-2026-ipkvm", Notes: "JetKVM unauth UI config: firmware version leak (CVE-2026-32294/32295 gating)"},
	{Vendor: "jetkvm", Product: "JetKVM", Path: "/device/status", Match: MatchExact, Tags: []string{"info", "fingerprint"}, Source: "eclypsium-2026-ipkvm", Notes: "JetKVM unauth status: reveals noPassword (no-auth) mode"},
	{Vendor: "nanokvm", Product: "NanoKVM", Path: "/api/vm/info", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "eclypsium-2026-ipkvm", Notes: "Sipeed NanoKVM unauth info API"},
	{Vendor: "nanokvm", Product: "NanoKVM", Path: "/api/network/wifi", Match: MatchExact, Tags: []string{"dynamic", "api"}, Source: "eclypsium-2026-ipkvm", Notes: "NanoKVM CVE-2026-32296 unauth endpoint; probe presence only (GET, no config write)"},
	{Vendor: "pikvm", Product: "PiKVM", Path: "/api/info", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "eclypsium-2026-ipkvm", Notes: "PiKVM kvmd /api/info (auth-gated on hardened units; open = no-auth posture)"},
	{Vendor: "tinypilot", Product: "TinyPilot", Path: "/api/status", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "eclypsium-2026-ipkvm", Notes: "TinyPilot status API; community edition ships with NO auth by default"},
	{Vendor: "tinypilot", Product: "TinyPilot", Path: "/api/version", Match: MatchExact, Tags: []string{"info", "api", "fingerprint", "version"}, Source: "eclypsium-2026-ipkvm", Notes: "TinyPilot version API (unauth on default community build)"},
	{Vendor: "tinypilot", Product: "TinyPilot", Path: "/ca.crt", Match: MatchExact, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis", Notes: "TinyPilot serves its PEM CA at /ca.crt (aliased tinypilot-ca.crt) with 200 and no session; strong TinyPilot fingerprint (nginx tinypilot.conf.j2)"},
	// PiKVM exposes an unauthenticated Redfish service tree (the only
	// auth_required=False GET besides /auth/login) - a high-confidence PiKVM marker.
	{Vendor: "pikvm", Product: "PiKVM", Path: "/redfish/v1", Match: MatchExact, Tags: []string{"info", "redfish", "static", "fingerprint"}, Source: "firmware-analysis", Notes: "PiKVM ships a benign unauth Redfish service root (#ServiceRoot with Managers+Systems); strong fingerprint"},

	// --- Console-server / PDU pre-auth endpoints. Safe GET-only fingerprint /
	// info-leak surfaces; no login is submitted here (the exposure checks report
	// these as fingerprint/candidacy).
	// Lantronix SLC8000 xwsd login page.
	{Vendor: "lantronix", Product: "SLC8000", Path: "/login.htm", Match: MatchExact, Tags: []string{"static", "login", "fingerprint"}, Source: "firmware-analysis", Notes: "SLC8000 xwsd login page; identifies Lantronix SecureLinx Console Manager pre-auth"},
	// Opengear OM2200 unauthenticated REST info endpoints + Bootstrap SPA.
	{Vendor: "opengear", Product: "OM2200", Path: "/api/v1/system/model_name", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth: leaks model name pre-auth (Opengear-unauth-rest-leak)"},
	{Vendor: "opengear", Product: "OM2200", Path: "/api/v1/system/banner", Match: MatchExact, Tags: []string{"info", "api", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth: login banner pre-auth"},
	{Vendor: "opengear", Product: "OM2200", Path: "/api/v1/system/local_password_policy", Match: MatchExact, Tags: []string{"info", "api"}, Source: "firmware-analysis", Notes: "unauth: password-hardening policy leak pre-auth"},
	{Vendor: "opengear", Product: "OM2200", Path: "/bootstrap/", Match: MatchPrefix, Tags: []string{"static", "fingerprint"}, Source: "firmware-analysis", Notes: "OM2200 ngcs single-page-app root; nginx hides Server header, 32-hex session_id cookie"},
	// Perle IOLAN web admin CGIs.
	{Vendor: "perle", Product: "IOLAN", Path: "/manage.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "fingerprint"}, Source: "firmware-analysis", Notes: "IOLAN web admin CGI; Perle fingerprint"},
	{Vendor: "perle", Product: "IOLAN", Path: "/tp-siab.cgi", Match: MatchExact, Tags: []string{"dynamic", "cgi", "fingerprint"}, Source: "firmware-analysis", Notes: "IOLAN TruePort-in-a-browser CGI; Perle fingerprint"},
	// ServerTech Sentry JAWS login page.
	{Vendor: "servertech", Product: "Sentry", Path: "/login.html", Match: MatchExact, Tags: []string{"static", "login", "fingerprint"}, Source: "firmware-analysis", Notes: "Sentry JAWS login page (cookie C=); Server Technology fingerprint"},
	// Rittal CMC III REST API (Pistache, security: - {} override) serves two
	// documents pre-auth: the OpenAPI spec (names the device) and a system
	// metrics object. Both are read-only information disclosures via GET.
	{Vendor: "rittal", Product: "CMC III", Path: "/rest/v1/openapi.yaml", Match: MatchExact, Tags: []string{"info", "rest", "static", "fingerprint"}, Source: "firmware-analysis", Notes: "unauth CMC III OpenAPI service document (names device + full REST map); rest-api-server security override"},
	{Vendor: "rittal", Product: "CMC III", Path: "/rest/v1/system/metrics", Match: MatchExact, Tags: []string{"info", "rest"}, Source: "firmware-analysis", Notes: "unauth CPU/memory/uptime/UnitsFailed JSON; rest-api-server security override"},

	// --- KB gap additions ---
	// Pre-auth info/session/state endpoints from per-vendor firmware analysis.
	// Endpoint has no Method field, so POST-only handlers note "POST:" in Notes;
	// query strings are stored in Notes alongside the base Path.
	{Vendor: "asrockrack", Product: "MegaRAC-SP", Path: "/redfish/v1/GlobalLuaTables", Match: MatchExact, Tags: []string{"info", "redfish"}, Source: "firmware-analysis", Notes: "pre-auth implementation endpoint; commonly empty or ordinary Redfish links"},
	{Vendor: "asus", Product: "ASMB", Path: "/wsman", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "R7A41134 pre-PAM Basic-auth parser; crash vs 401 = vuln build"},
	{Vendor: "avocent", Product: "ACS8000", Path: "/redfish/v1/index.json", Match: MatchExact, Tags: []string{"info", "redfish", "static"}, Source: "firmware-analysis", Notes: "static Redfish service root"},
	{Vendor: "avocent", Product: "ACS8000", Path: "/appliance/avtrans", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: reaches root uicontrold login validator; no auth/SSL"},
	{Vendor: "cisco", Product: "CIMC", Path: "/api/cimcInfo.json", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "hostname/model/generation/fw_version/serial (needs browser headers)"},
	{Vendor: "cisco", Product: "CIMC", Path: "/nuova", Match: MatchExact, Tags: []string{"auth", "state"}, Source: "firmware-analysis", Notes: "POST: outCookie session; configConfMo aaaUser = pre-auth pw reset (CVE-2026-20093)"},
	{Vendor: "blikvm", Product: "BliKVM", Path: "/api/auth/state", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "auth/session state"},
	{Vendor: "cyberpower", Product: "RMCARD", Path: "/api/login/status", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "login-state JSON; Set-Cookie cocp"},
	{Vendor: "dell", Product: "iDRAC", Path: "/sysmgmt/2012/server/configgroup/iDRAC.userdomain", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "user-domain config"},
	{Vendor: "dell", Product: "iDRAC", Path: "/cgi-bin/discover/", Match: MatchExact, Tags: []string{"info", "static"}, Source: "firmware-analysis", Notes: "static discover.xml"},
	{Vendor: "eaton", Product: "Network-M", Path: "/set_obj.xml", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "pre-auth root ipm_server overflow, not in auth.require"},
	{Vendor: "eaton", Product: "Network-M", Path: "/etn/v1/comm/identification", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "manufacturer/MAC/UUID JSON"},
	{Vendor: "gigabyte", Product: "MegaRAC-SP", Path: "/redfish/v1/GlobalLuaTables", Match: MatchExact, Tags: []string{"info", "redfish"}, Source: "firmware-analysis", Notes: "pre-auth implementation endpoint (AST2600 13.06.26); no sensitive table data observed"},
	{Vendor: "hpe", Product: "iLO", Path: "/xmldata", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "query ?item=CpqKey; iLO license-activation key"},
	{Vendor: "huawei", Product: "iBMC", Path: "/UI/Rest/Login", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "FQDN/hostname/product/LDAP/banner/lockout (openUBMC)"},
	{Vendor: "huawei", Product: "iBMC", Path: "/UI/Rest/AccessMgnt/Encryption", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "runtime RSA pubkey (per-process)"},
	{Vendor: "lantronix", Product: "IONMM", Path: "/cgi", Match: MatchExact, Tags: []string{"state", "cgi"}, Source: "firmware-analysis", Notes: "query ?login=exit; IONMM pre-auth root RCE via chassis3/SID cookie"},
	{Vendor: "lantronix", Product: "NTC-552", Path: "/root_pass", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: NTC-552 pre-auth root-pw guess oracle"},
	{Vendor: "jetkvm", Product: "JetKVM", Path: "/metrics", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "Prometheus text, no creds"},
	{Vendor: "lenovo", Product: "XCC", Path: "/nonauth/secmode", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: Edge NIC/secmode reconfig; client 32-char token gated"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/trespass", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "serial/machine-type/platform"},
	{Vendor: "lenovo", Product: "XCC", Path: "/api/providers/sso_authorization", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: SSRF/open-redirect; TLS verify off; X-Host redirect"},
	{Vendor: "intel", Product: "Integrated BMC", Path: "/redfish/v1/", Match: MatchExact, Tags: []string{"info", "redfish"}, Source: "firmware-analysis", Notes: "FirmwareVersion 2.94.x"},
	{Vendor: "moxa", Product: "NPort", Path: "/Login.htm", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "tokens FakeChallenge/encodePassword/getServerLocLen/${NPORT.JS}"},
	{Vendor: "nanokvm", Product: "NanoKVM", Path: "/api/network/wifi/verify", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: X-AP-Key constant-time gate + ~2s delay (outside CheckToken)"},
	{Vendor: "nanokvm", Product: "NanoKVM", Path: "/api/auth/login", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "POST: {token:disabled} => uncredentialed"},
	{Vendor: "nanokvm", Product: "NanoKVM", Path: "/assets/", Match: MatchPrefix, Tags: []string{"info", "static"}, Source: "firmware-analysis", Notes: "encrypt-*.js literal nanokvm-sipeed-2024 fleet AES key"},
	{Vendor: "nvidia", Product: "BMC", Path: "/redfish/v1", Match: MatchExact, Tags: []string{"info", "redfish"}, Source: "firmware-analysis", Notes: "service root w/ Oem.Nvidia"},
	{Vendor: "opengear", Product: "OM2200", Path: "/api/v1/test", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "POST: uncharacterized pre-auth stub (OM2200)"},
	{Vendor: "perle", Product: "IOLAN", Path: "/tp-main.cgi", Match: MatchExact, Tags: []string{"info", "cgi"}, Source: "firmware-analysis", Notes: "IOLAN TruePort config fingerprint"},
	{Vendor: "pikvm", Product: "PiKVM", Path: "/api/auth/check", Match: MatchExact, Tags: []string{"auth"}, Source: "firmware-analysis", Notes: "200 when X-KVMD-User/Passwd valid = unthrottled default-cred probe"},
	{Vendor: "raritan", Product: "PX", Path: "/cgi-bin/login_options.cgi", Match: MatchExact, Tags: []string{"info", "cgi"}, Source: "firmware-analysis", Notes: "manufacturer/RSA banner/cascade_master_host JSON"},
	{Vendor: "servertech", Product: "Sentry", Path: "/CDU/summary", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "Switched CDU UI fingerprint"},
	{Vendor: "sierra", Product: "AirLink ALEOS", Path: "/xml/GetPublic.xml", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "POST: CVE-2018-4063 net-ready/RSSI/GPS (urn:acemanager)"},
	{Vendor: "tyan", Product: "MegaRAC-SP", Path: "/redfishSCPD.xml", Match: MatchExact, Tags: []string{"info", "static"}, Source: "firmware-analysis", Notes: "UPnP SCPD model/identity (SSDP-advertised)"},
	{Vendor: "vertiv", Product: "IntelliSlot Unity", Path: "/web/cardinfo.json", Match: MatchExact, Tags: []string{"info"}, Source: "firmware-analysis", Notes: "state configured/unconfigured, version, sysName, eth0 MAC"},
	{Vendor: "vertiv", Product: "IntelliSlot Unity", Path: "/webapi/webadduser", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: creates first admin on un-provisioned card"},
	{Vendor: "westermo", Product: "WeOS", Path: "/alarm.cgi", Match: MatchExact, Tags: []string{"info", "cgi"}, Source: "firmware-analysis", Notes: "alarm states text/plain, no session/CSRF"},
	{Vendor: "tinypilot", Product: "TinyPilot", Path: "/api/user", Match: MatchExact, Tags: []string{"state"}, Source: "firmware-analysis", Notes: "POST: creates first admin + auto-login on un-provisioned unit (ships-open)"},
}

// AggregatedTarget deduplicates a path while preserving vendor hints and tags.
type AggregatedTarget struct {
	Path     string
	Match    MatchType
	Vendors  []string
	Products []string
	Tags     []string
	Sources  []string
	Notes    []string
}

// AggregatedTargets returns the unique set of probe targets to sweep.
func AggregatedTargets() []AggregatedTarget {
	byKey := map[string]*AggregatedTarget{}
	for _, ep := range Corpus {
		key := string(ep.Match) + "\x00" + ep.Path
		tgt := byKey[key]
		if tgt == nil {
			tgt = &AggregatedTarget{Path: ep.Path, Match: ep.Match}
			byKey[key] = tgt
		}
		tgt.Vendors = appendUnique(tgt.Vendors, ep.Vendor)
		tgt.Products = appendUnique(tgt.Products, ep.Product)
		for _, tag := range ep.Tags {
			tgt.Tags = appendUnique(tgt.Tags, tag)
		}
		tgt.Sources = appendUnique(tgt.Sources, ep.Source)
		if ep.Notes != "" {
			tgt.Notes = appendUnique(tgt.Notes, ep.Notes)
		}
	}
	out := make([]AggregatedTarget, 0, len(byKey))
	for _, tgt := range byKey {
		sort.Strings(tgt.Vendors)
		sort.Strings(tgt.Products)
		sort.Strings(tgt.Tags)
		sort.Strings(tgt.Sources)
		sort.Strings(tgt.Notes)
		out = append(out, *tgt)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Match < out[j].Match
	})
	return out
}

func appendUnique(dst []string, value string) []string {
	if value == "" {
		return dst
	}
	if slices.Contains(dst, value) {
		return dst
	}
	return append(dst, value)
}
