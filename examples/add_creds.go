package examples

import (
	"github.com/runZeroInc/oobscan/pkg/creds"
)

// AddCredentialRow shows the one-line change that teaches oobscan a new default
// credential. In a real contribution you append the row to creds.Table in
// pkg/creds/table.go; nothing else needs to change -- the crack/spray
// pipeline picks it up via creds.CredsFor(vendor, class).
//
// Guidelines:
//   - Vendor is a lowercase slug matching the identify/oob vendor keys
//     ("dell", "supermicro", "hpe", ...); "" means generic/cross-vendor.
//   - Class scopes the login surface (ClassIPMI/ClassRedfish/ClassHTTP/ClassSSH,
//     or ClassAny). Don't spray a Redfish-only default over IPMI RAKP.
//   - Source records provenance so the knowledge base stays auditable.
func AddCredentialRow() creds.Credential {
	return creds.Credential{
		Vendor:   "example",
		Class:    creds.ClassIPMI,
		Username: "ADMIN",
		Password: "example-default",
		Source:   "vendor-doc",
		Notes:    "illustrative row; append the literal to creds.Table",
	}
}

// LookupDefaults shows the read side: CredsFor returns the vendor-prioritized
// candidate list the offline RAKP cracker walks (vendor defaults first, then the
// generic pool), scoped to the login surface.
func LookupDefaults(vendor string) []creds.Credential {
	return creds.CredsFor(vendor, creds.ClassIPMI)
}
