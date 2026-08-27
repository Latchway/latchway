// Package api embeds the canonical machine-readable contracts used by the
// runtime. The source files in this directory remain the single source of
// truth for every generated bundle and server-side validation gate.
package api

import _ "embed"

// configSchema is the canonical EnvironmentConfig JSON Schema.
//
//go:embed config.schema.json
var configSchema []byte

// ConfigSchema returns a defensive copy of the canonical configuration schema.
func ConfigSchema() []byte {
	result := make([]byte, len(configSchema))
	copy(result, configSchema)
	return result
}
