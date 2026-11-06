package auth

import (
	"context"
	"fmt"
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/filters"
	"github.com/openshift/osin"
)

// ReadStore is an ActivityPub storage implementation that can
// return a valid Item object based on its IRI.
// This functionality is used by both client to server and server to server
// authorization mechanisms.
type ReadStore interface {
	// Load returns an Item or an ItemCollection from an IRI
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
}

// AccessStore is an ActivityPub storage implementation that can
// be used to retrieve actors and their generated OAuth2 access tokens.
// This functionality is used only by the client to server authorization mechanism.
type AccessStore interface {
	ReadStore
	LoadAccess(string) (*osin.AccessData, error)
}

// ActivityPubClient is an ActivityPub client that can retrieve remote items
// based on their IRI.
// It gets used when trying to dereference remote Actors based on their key IDs,
// in the process of validating the HTTP-Signatures based authorization headers
// for server to server, or secure fetch requests.
type ActivityPubClient interface {
	Do(*http.Request) (*http.Response, error)
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
}

type config struct {
	c    ActivityPubClient
	ncFn httpsig.NonceGetter
	ost  AccessStore
	ast  ReadStore
	l    log.Logger
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

func WithLogger(l log.Logger) InitFn {
	return func(conf *config) {
		conf.l = l
	}
}

// WithStorage sets the storage for verifying actors in local storage.
func WithStorage(s ReadStore) InitFn {
	return func(conf *config) {
		conf.ast = s
	}
}

// WithOAuth2Storage sets the storage for verifying OAuth Access tokens
// against the local actor storage.
func WithOAuth2Storage(s AccessStore) InitFn {
	return func(conf *config) {
		conf.ost = s
	}
}

func WithClient(cl ActivityPubClient) InitFn {
	return func(c *config) {
		c.c = cl
	}
}

func WithNonceChecker(nc httpsig.NonceGetter) InitFn {
	return func(c *config) {
		c.ncFn = nc
	}
}

func Verifier(initFns ...InitFn) actorResolver {
	return actorResolver(Config(initFns...))
}

// Verify reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (a actorResolver) Verify(r *http.Request) (vocab.Actor, error) {
	if a.ost == nil {
		return AnonymousActor, errInvalidStorage
	}
	if r == nil {
		return AnonymousActor, nil
	}

	logCtx := log.Ctx{}
	logCtx["req"] = fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI())

	var typ string
	var auth string

	if auth = r.Header.Get("Signature"); auth != "" {
		typ = "Signature"
	} else if auth = r.Header.Get("Authorization"); auth != "" {
		typ, _ = getAuthorization(auth)
	}

	switch typ {
	case "Bearer":
		ol := oauthVerifier{st: a.ost}
		return ol.Verify(r)
	case "Signature":
		kl := httpSigVerifier{
			loader: &localRemoteLoader{c: a.c, st: a.ast},
			l:      a.l,
		}
		return kl.Verify(r)
	default:
		return AnonymousActor, nil
	}
}
