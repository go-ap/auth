//go:build dev

package auth

import "time"

var (
	sigValidDeltaDuration = 10 * time.Minute
	sigMaxAgeDuration     = 10 * 365 * 24 * time.Hour
)
