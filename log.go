package auth

import (
	log "git.sr.ht/~mariusor/lw"
)

// logger is our internal implementation of an OSIN compatible logger.
type logger struct {
	log.Logger
}

func (l logger) Printf(format string, v ...any) {
	if l.Logger == nil {
		return
	}
	l.Logger.Infof(format, v...)
}
