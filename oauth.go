package auth

import (
	"github.com/go-ap/client"
	"github.com/go-ap/storage"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

func New(url string, os osin.Storage, st storage.ReadStore, l logrus.FieldLogger) (*Server, error) {
	osin, err := NewServer(os, l)
	if err != nil {
		return nil, err
	}
	return &Server{
		Server:  osin,
		baseURL: url,
		account: Account(AnonymousActor),
		cl:      client.New(),
		st:      st,
		l:       l,
	}, err
}
