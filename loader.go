package auth

import (
	"fmt"
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/filters"
	"github.com/openshift/osin"
)

// readStore
type readStore interface {
	// Load returns an Item or an ItemCollection from an IRI
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
}

type oauthStore interface {
	readStore
	LoadAccess(string) (*osin.AccessData, error)
}

type ActivityPubClient interface {
	Do(r *http.Request) (*http.Response, error)
	LoadIRI(id vocab.IRI) (vocab.Item, error)
}

type config struct {
	ignore vocab.IRIs
	c      ActivityPubClient
	st     oauthStore
	l      log.Logger
}

// actorResolver is a used for resolving actors either in local storage or remotely
type actorResolver config

func Config(initFns ...InitFn) config {
	c := config{l: log.Nil()}
	for _, fn := range initFns {
		fn(&c)
	}
	return c
}

type InitFn = func(*config)

func WithIgnoreList(iris ...vocab.IRI) InitFn {
	return func(conf *config) {
		conf.ignore = iris
	}
}

func WithLogger(l log.Logger) InitFn {
	return func(conf *config) {
		conf.l = l
	}
}

func WithStorage(s oauthStore) InitFn {
	return func(conf *config) {
		conf.st = s
	}
}

func WithClient(cl ActivityPubClient) InitFn {
	return func(c *config) {
		c.c = cl
	}
}

func Resolver(initFns ...InitFn) actorResolver {
	return actorResolver(Config(initFns...))
}

// Verify reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (a actorResolver) Verify(r *http.Request) (vocab.Actor, error) {
	if a.st == nil {
		return AnonymousActor, errInvalidStorage
	}
	if r == nil {
		return AnonymousActor, nil
	}

	logCtx := log.Ctx{}
	logCtx["req"] = fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI())

	var header string
	var typ string
	var auth string

	if auth = r.Header.Get("Signature"); auth != "" {
		typ = "Signature"
		header = auth
	} else if auth = r.Header.Get("Authorization"); auth != "" {
		header = auth
		typ, auth = getAuthorization(header)
	}

	switch typ {
	case "Bearer":
		ol := oauthLoader{st: a.st}
		return ol.Verify(r)
	case "Signature":
		kl := httpSigVerifier{
			ignore: a.ignore,
			loader: keyLoader{c: a.c, st: a.st},
			l:      a.l,
		}
		return kl.Verify(r)
	default:
		return AnonymousActor, nil
	}
}
