package auth

import (
	log "git.sr.ht/~mariusor/lw"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

type OptionFn func(s *Server) error

func WithURL(u string) OptionFn {
	return func(s *Server) error {
		s.baseURL = u
		return nil
	}
}

func WithStorage(st ReadStore) OptionFn {
	return func(s *Server) error {
		s.st = st
		if _, ok := st.(osin.Storage); !ok {
			return errors.Newf("invalid osin storage %T", st)
		}
		return nil
	}
}

func WithClient(cl client.Basic) OptionFn {
	return func(s *Server) error {
		s.cl = cl
		return nil
	}
}

func WithLogger(l log.Logger) OptionFn {
	return func(s *Server) error {
		s.l = l
		return nil
	}
}
func New(optFns ...OptionFn) (*Server, error) {
	s := new(Server)
	s.account = Account(AnonymousActor)

	for _, fn := range optFns {
		if err := fn(s); err != nil {
			return s, err
		}
	}
	if s.st == nil {
		return nil, errors.Newf("Storage was not set")
	}
	os, ok := s.st.(osin.Storage)
	if !ok {
		return nil, errors.Newf("Storage type %T is not compatible with %T", s.st, osin.Storage(nil))
	}
	ss, err := NewServer(os, s.l)
	if err != nil {
		return nil, err
	}
	s.Server = ss
	return s, nil
}
