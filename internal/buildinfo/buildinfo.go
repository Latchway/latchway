// Package buildinfo exposes values injected by release builds.
package buildinfo

var (
	Version = "1.1.1"
	Commit  = "unknown"
	Date    = "unknown"
)

const (
	ContractVersion        = "1.1.0"
	ProtocolVersion        = "3"
	MinimumProtocolVersion = 1
	CurrentProtocolVersion = 3
)

// SupportedProtocolVersions returns the complete ordered wire range accepted
// by this server. Protocol 1 remains available for the legacy installation
// flow, protocol 2 retains its family/component contract, and protocol 3 adds
// the opt-in shared native app declaration.
func SupportedProtocolVersions() []int {
	return []int{1, 2, 3}
}

// SupportsProtocolVersion reports whether the canonical decimal header value
// names a wire version accepted by this server. Leading zeroes and combined
// header values deliberately fail closed.
func SupportsProtocolVersion(value string) bool {
	return value == "1" || value == "2" || value == ProtocolVersion
}

// Info is the stable machine-readable build description.
type Info struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuildDate       string `json:"build_date"`
	ContractVersion string `json:"contract_version"`
	ProtocolVersion string `json:"protocol_version"`
}

// Current returns build metadata without inspecting mutable process state.
func Current() Info {
	return Info{
		Version:         Version,
		Commit:          Commit,
		BuildDate:       Date,
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
	}
}
