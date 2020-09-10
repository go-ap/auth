package auth

import (
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"net/http"
)

type loggerFn func(logrus.Fields, string, ...interface{})

type logger struct {
	logFn loggerFn
	errFn loggerFn
}

var emptyLogFn = func(logrus.Fields, string, ...interface{}) {}

func (l logger) Printf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Errorf(format string, v ...interface{}) {
	l.errFn(nil, format, v...)
}
func (l logger) Warningf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Infof(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
}
func (l logger) Debugf(format string, v ...interface{}) {
	l.logFn(nil, format, v...)
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

	logFn := emptyLogFn
	if l != nil {
		logFn = func(ctx logrus.Fields, format string, v ...interface{}) {
			l.WithFields(ctx).Infof(format, v...)
		}
	}
	s.Logger = logger{logFn: logFn}

	return s, nil
}
