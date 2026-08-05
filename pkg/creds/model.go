package creds

type DeviceClass string

const (
	ClassAny     DeviceClass = ""
	ClassIPMI    DeviceClass = "ipmi"
	ClassRedfish DeviceClass = "redfish"
	ClassHTTP    DeviceClass = "http"
	ClassSSH     DeviceClass = "ssh"
)

type Credential struct {
	Vendor   string
	Class    DeviceClass
	Username string
	Password string
	Source   string
	CVE      string
	Notes    string
}
