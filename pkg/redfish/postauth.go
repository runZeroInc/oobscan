package redfish

type PostAuthSnapshot struct {
	Method string     `json:"method,omitempty"`
	Via    string     `json:"via,omitempty"`
	User   string     `json:"username,omitempty"`
	Source string     `json:"source,omitempty"`
	Info   SystemInfo `json:"info"`
}
