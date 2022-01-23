package auth

import (
	pub "github.com/go-ap/activitypub"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/client"
	"github.com/go-ap/storage"
	"github.com/go-chi/chi"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"net/http"
)

type Account pub.Actor

func (a *Account) IsLogged() bool {
	if a == nil {
		return false
	}
	if a.ID == pub.PublicNS {
		return false
	}
	return true
}

type Server struct {
	Server  *osin.Server
	baseURL string
	account Account
	cl      client.Basic
	st      storage.ReadStore
	l       logrus.FieldLogger
}

// ID is the type of authorization that IndieAuth is using
const ID = osin.AuthorizeRequestType("id")

func NewServer(store osin.Storage, l logrus.FieldLogger) (*osin.Server, error) {
	config := osin.ServerConfig{
		AuthorizationExpiration:   86400,
		AccessExpiration:          2678400,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN, ID},
		AllowedAccessTypes:        osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.PASSWORD /*osin.CLIENT_CREDENTIALS*/},
		ErrorStatusCode:           http.StatusForbidden,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   true,
		RedirectUriSeparator:      "\n",
		//RequirePKCEForPublicClients: true,
	}
	s := osin.NewServer(&config, store)

	logFn := log.EmptyLogFn
	errFn := log.EmptyLogFn
	if l != nil {
		logFn = func(ctx logrus.Fields, format string, v ...interface{}) {
			l.WithFields(ctx).Infof(format, v...)
		}
		errFn = func(ctx logrus.Fields, format string, v ...interface{}) {
			l.WithFields(ctx).Infof(format, v...)
		}
	}
	var err error
	s.Logger, err = log.New(log.LogFn(logFn), log.ErrFn(errFn))
	return s, err
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
