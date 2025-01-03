package auth

import (
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
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
	localURLs vocab.IRIs
	account   Account
	cl        Client
	l         log.Logger
}

// ID is the type of authorization that IndieAuth is using
const ID = osin.AuthorizeRequestType("id")

var (
	DefaultAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN, ID}
	DefaultAccessTypes    = osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.PASSWORD /*osin.CLIENT_CREDENTIALS*/}

	DefaultConfig = osin.ServerConfig{
		AuthorizationExpiration:   86400,
		AccessExpiration:          2678400,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     DefaultAuthorizeTypes,
		AllowedAccessTypes:        DefaultAccessTypes,
		ErrorStatusCode:           http.StatusForbidden,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   true,
		RedirectUriSeparator:      "\n",
		//RequirePKCEForPublicClients: true,
	}
)

func NewServer(store osin.Storage, l log.Logger) (*osin.Server, error) {
	s := osin.NewServer(&DefaultConfig, store)

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
