package auth

import (
	"github.com/go-ap/activitypub/client"
	"github.com/go-ap/storage"
	"github.com/go-chi/chi"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

type Account struct {
	actor Person
}

func (a *Account) IsLogged() bool {
	return true
}

type Server struct {
	baseURL string
	account Account
	os      *osin.Server
	cl      client.Client
	st      storage.ActorLoader
	l       logrus.FieldLogger
}

func New(url string, os *osin.Server, st storage.ActorLoader, l logrus.FieldLogger) *Server {
	return &Server{
		baseURL: url,
		account: Account{actor:AnonymousActor},
		os:      os,
		cl:      client.NewClient(),
		st:      st,
		l:       l,
	}
}

func (s Server) Routes(r chi.Router) chi.Routes {
	return r.Route("/oauth", func(r chi.Router) {
		// Authorization code endpoint
		r.With(s.ValidateLoggedIn()).Get("/authorize", s.Authorize)
		r.Post("/authorize", s.Authorize)
		// Access token endpoint
		r.Post("/token", s.Token)
	})
}

