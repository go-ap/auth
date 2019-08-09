package auth

import (
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"net/http"
)

type loggerFn func(logrus.Fields, string, ...interface{})

type logger struct {
	l loggerFn
}

func (l logger) Printf(format string, v ...interface{}) {
	l.l(nil, format, v...)
}

func NewOAuth2Server(store osin.Storage, l logrus.FieldLogger) (*osin.Server, error) {
	config := osin.ServerConfig{
		AuthorizationExpiration:   86400,
		AccessExpiration:          2678400,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN},
		AllowedAccessTypes:        osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.PASSWORD, /*osin.CLIENT_CREDENTIALS*/},
		ErrorStatusCode:           http.StatusForbidden,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   true,
		RedirectUriSeparator:      "\n",
		//RequirePKCEForPublicClients: true,
	}
	s := osin.NewServer(&config, store)

	// TODO(marius): implement actual logic for this
	var log loggerFn
	log = func(f logrus.Fields, s string, p ...interface{}) {}

	s.Logger = logger{l: log}
	return s, nil
}
