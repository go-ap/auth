//go:build dev

package auth

import "time"

var (
	sigValidDeltaDuration = 10 * time.Minute
	// NOTE(marius): hopefully we have better tests in the next decade so we don't have to rely on this value
	sigMaxAgeDuration = 10 * 365 * 24 * time.Hour
)
