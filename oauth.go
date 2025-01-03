package auth

import (
	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

type OptionFn func(s *Server) error

func WithIRI(i ...vocab.IRI) OptionFn {
	return func(s *Server) error {
		if s.localURLs == nil {
			s.localURLs = make(vocab.IRIs, 0)
		}
		s.localURLs = i
		return nil
	}
}

func WithURL(uu ...string) OptionFn {
	return func(s *Server) error {
		if s.localURLs == nil {
			s.localURLs = make(vocab.IRIs, 0)
		}
		for _, u := range uu {
			s.localURLs = append(s.localURLs, vocab.IRI(u))
		}
		return nil
	}
}

func WithStorage(st oauthStore) OptionFn {
	if os, ok := st.(osin.Storage); ok {
		return func(s *Server) error {
			ss, err := NewServer(os, s.l)
			if err != nil {
				return err
			}
			s.Server = ss
			s.Storage = os
			return nil
		}
	}
	return func(s *Server) error {
		return errors.Newf("invalid osin storage %T", st)
	}
}

func WithClient(cl Client) OptionFn {
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
	if s.Storage == nil {
		return nil, errors.Newf("st was not set")
	}
	return s, nil
}
