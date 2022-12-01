package auth

import (
	log "git.sr.ht/~mariusor/lw"
	"github.com/go-ap/client"
	"github.com/openshift/osin"
)

func New(url string, os osin.Storage, st ReadStore, cl client.Basic, l log.Logger) (*Server, error) {
	osin, err := NewServer(os, l)
	if err != nil {
		return nil, err
	}
	return &Server{
		Server:  osin,
		baseURL: url,
		account: Account(AnonymousActor),
		cl:      cl,
		st:      st,
		l:       l,
	}, err
}
