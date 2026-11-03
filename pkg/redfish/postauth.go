package redfish

// PostAuthSnapshot is the normalized Redfish post-auth data captured by
// authenticated checks. It records how authentication succeeded plus the
// inventory fields recovered from the authenticated session.
type PostAuthSnapshot struct {
	Method string     `json:"method,omitempty"` // defaultCreds | providedCreds | mtls
	Via    string     `json:"via,omitempty"`    // session | basic | mtls
	User   string     `json:"username,omitempty"`
	Source string     `json:"source,omitempty"`
	Info   SystemInfo `json:"info"`
}
