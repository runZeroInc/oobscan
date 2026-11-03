package creds

// DeviceClass scopes a credential to the login surface it applies to. A
// credential with ClassAny matches every surface; otherwise the pipeline only
// tries it against a matching surface (e.g. don't spray a Redfish-only default
// over IPMI RAKP).
type DeviceClass string

const (
	ClassAny     DeviceClass = ""        // matches any login surface
	ClassIPMI    DeviceClass = "ipmi"    // IPMI 2.0 RAKP / IPMI 1.5 session login
	ClassRedfish DeviceClass = "redfish" // Redfish HTTP API
	ClassHTTP    DeviceClass = "http"    // vendor web UI (iLO / iDRAC / XCC / CIMC)
	ClassSSH     DeviceClass = "ssh"     // BMC shell over SSH
)

// Credential is one row of the default-credential knowledge base. Add a row to
// Table to teach the scanner a new default; nothing else needs to change.
type Credential struct {
	Vendor   string      // lowercase slug ("dell", "supermicro", "ami"); "" = generic/cross-vendor
	Class    DeviceClass // login surface this default applies to; ClassAny = all
	Username string      //
	Password string      //
	Source   string      // provenance token for the knowledge-base row
	CVE      string      // associated CVE, when the default is itself a tracked issue
	Notes    string      // free-form context for the knowledge base
}
