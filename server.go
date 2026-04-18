package auth

import (
	"net/http"

	"git.sr.ht/~mariusor/lw"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

type Server struct {
	*osin.Server
}

// ID is the type of authorization that IndieAuth is using
const ID = osin.AuthorizeRequestType("id")

var (
	DefaultAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN, ID}
	DefaultAccessTypes    = osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.PASSWORD, osin.CLIENT_CREDENTIALS}

	DefaultConfig = osin.ServerConfig{
		AuthorizationExpiration:     86400,
		AccessExpiration:            2678400,
		TokenType:                   "Bearer",
		AllowedAuthorizeTypes:       DefaultAuthorizeTypes,
		AllowedAccessTypes:          DefaultAccessTypes,
		ErrorStatusCode:             http.StatusForbidden,
		AllowClientSecretInParams:   false,
		AllowGetAccessRequest:       false,
		RetainTokenAfterRefresh:     true,
		RedirectUriSeparator:        "\n",
		RequirePKCEForPublicClients: true,
	}
)

type OptionFn func(s *osin.Server) error

func WithStorage(st oauthStore) OptionFn {
	if os, ok := st.(osin.Storage); ok {
		return func(s *osin.Server) error {
			s.Storage = os
			return nil
		}
	}
	return func(s *osin.Server) error {
		return errors.Newf("invalid osin storage %T", st)
	}
}

func WithLogger(l lw.Logger) OptionFn {
	return func(s *osin.Server) error {
		if l != nil {
			s.Logger = logger{Logger: l}
		}
		return nil
	}
}

func New(optFns ...OptionFn) (*Server, error) {
	s := &Server{Server: osin.NewServer(&DefaultConfig, nil)}

	for _, fn := range optFns {
		if err := fn(s.Server); err != nil {
			return s, err
		}
	}
	if s.Storage == nil {
		return nil, errors.Newf("storage was not set for the authorization server")
	}

	return s, nil
}

type Metadata struct {
	Pw         []byte `jsonld:"pw,omitempty"`
	PrivateKey []byte `jsonld:"key,omitempty"`
}
