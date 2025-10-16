package identity

// User represents the identity record returned to downstream tooling.
type User struct {
	ID          string   `json:"id" yaml:"id"`
	Email       string   `json:"email" yaml:"email"`
	DisplayName string   `json:"displayName" yaml:"displayName"`
	Roles       []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	Groups      []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Devices     []Device `json:"devices,omitempty" yaml:"devices,omitempty"`
}

// Device summarizes a Tailscale node or other resource associated with a user.
type Device struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	TailnetIP   string `json:"tailnetIp,omitempty" yaml:"tailnetIp,omitempty"`
	LastSeenRFC string `json:"lastSeen,omitempty" yaml:"lastSeen,omitempty"`
}
