// Package migrations owns the forward-only SQL migration bundle.
package migrations

import "embed"

// Files contains every released database migration.
//
//go:embed *.sql
var Files embed.FS
