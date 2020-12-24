package auth

import (
	"github.com/go-ap/auth/internal/log"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"net/http"
)

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
