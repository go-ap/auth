package auth

import (
	"reflect"
	"time"
)

const (
	clientsBucket   = "clients"
	authorizeBucket = "authorize"
	accessBucket    = "access"
	refreshBucket   = "refresh"
)

type cl struct {
	Id          string
	Secret      string
	RedirectUri string
	Extra       interface{}
}

type auth struct {
	Client      string
	Code        string
	ExpiresIn   time.Duration
	Scope       string
	RedirectURI string
	State       string
	CreatedAt   time.Time
	Extra       interface{}
}

type acc struct {
	Client       string
	Authorize    string
	Previous     string
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
	Scope        string
	RedirectURI  string
	CreatedAt    time.Time
	Extra        interface{}
}

type ref struct {
	Access string
}

func interfaceIsNil(c interface{}) bool {
	return reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()
}
