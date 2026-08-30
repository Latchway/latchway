// Package buildinfo exposes values injected by release builds.
package buildinfo

var (
	Version = "1.0.0-rc.1"
	Commit  = "unknown"
	Date    = "unknown"
)

const (
	ContractVersion = "0.5.1"
	ProtocolVersion = "1"
)

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
