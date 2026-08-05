package examples

import (
	"github.com/runZeroInc/oobscan/pkg/creds"
)

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

func LookupDefaults(vendor string) []creds.Credential {
	return creds.CredsFor(vendor, creds.ClassIPMI)
}
