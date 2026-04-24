// Package migrations embeds the SQL migration files so goose can apply
// them from anywhere in the binary (pg.Migrate, slither-db CLI, tests).
// Migrations themselves are reviewed as plain SQL — this file is only
// the embed anchor.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
