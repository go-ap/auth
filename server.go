package auth

import (
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-chi/chi/v5"
	"github.com/openshift/osin"
)

type Account vocab.Actor

func (a *Account) IsLogged() bool {
	if a == nil {
		return false
	}
	if a.ID == vocab.PublicNS {
		return false
	}
	return true
}

type Server struct {
	*osin.Server
	baseURL string
	account Account
	cl      client.Basic
	st      ReadStore
	l       log.Logger
}

// ID is the type of authorization that IndieAuth is using
const ID = osin.AuthorizeRequestType("id")

func NewServer(store osin.Storage, l log.Logger) (*osin.Server, error) {
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

	logFn := EmptyLogFn
	errFn := EmptyLogFn
	if l != nil {
		logFn = func(ctx log.Ctx, format string, v ...interface{}) {
			l.WithContext(ctx).Infof(format, v...)
		}
		errFn = func(ctx log.Ctx, format string, v ...interface{}) {
			l.WithContext(ctx).Infof(format, v...)
		}
	}
	var err error
	s.Logger, err = NewLogger(LogFn(logFn), ErrFn(errFn))
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
