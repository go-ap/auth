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
	os     *osin.Server
	cl     client.Client
	loader storage.ActorLoader
	l      logrus.FieldLogger
}

func (s Server) Routes(r chi.Router) chi.Routes {
	return r.Route("/oauth", func(r chi.Router) {
		//r.Use(h.NeedsSessions)
		// Authorization code endpoint
		r.With(s.ValidateLoggedIn()).Get("/authorize", s.Authorize)
		r.Post("/authorize", s.Authorize)
		// Access token endpoint
		r.Post("/token", s.Token)
	})
}
