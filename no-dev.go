//go:build !dev

package auth

import "time"

var (
	sigValidDeltaDuration = time.Minute
	sigMaxAgeDuration     = 30 * time.Second
)
