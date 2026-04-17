package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
)

type Client interface {
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
}

type config struct {
	baseURL    string
	ignore     vocab.IRIs
	c          Client
	st         oauthStore
	logFn      LoggerFn
	iriIsLocal func(vocab.IRI) bool
}

// actorResolver is a used for resolving actors either in local storage or remotely
type actorResolver config

// ActorVerifier verifies if a [http.Request] contains information about an ActivityPub [vocab.Actor]
// that has operated it.
type ActorVerifier interface {
	// Verify validates a request for the existence of an authorized ActivityPub [vocab.Actor] that has
	// operated it.
	Verify(*http.Request) (vocab.Actor, error)
}

func Config(cl Client, initFns ...ConfigInitFn) config {
	c := config{c: cl}
	for _, fn := range initFns {
		fn(&c)
	}
	return c
}

func Resolver(cl Client, initFns ...ConfigInitFn) ActorVerifier {
	s := actorResolver(Config(cl, initFns...))
	return &s
}

type ConfigInitFn = func(*config)

func ConfigWithIgnoreList(iris ...vocab.IRI) ConfigInitFn {
	return func(conf *config) {
		conf.ignore = iris
	}
}

func ConfigWithLocalIRIFn(fn func(vocab.IRI) bool) ConfigInitFn {
	return func(conf *config) {
		conf.iriIsLocal = fn
	}
}

func ConfigWithLogger(l LoggerFn) ConfigInitFn {
	return func(conf *config) {
		conf.logFn = l
	}
}

func ConfigWithStorage(s oauthStore) ConfigInitFn {
	return func(conf *config) {
		conf.st = s
	}
}

// LoadRemoteKey fetches a remote Public Key and returns it's owner.
func LoadRemoteKey(ctx context.Context, c Client, iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	cl := client.HTTPClient(c.(*client.C))
	resp, err := cl.Get(iri.String())
	if err != nil {
		return AnonymousActor, nil, err
	}
	if resp == nil {
		return AnonymousActor, nil, errors.NotFoundf("unable to load iri %s", iri)
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return AnonymousActor, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusGone, http.StatusNotModified:
		// OK
	default:
		return AnonymousActor, nil, errors.NewFromStatus(resp.StatusCode, "unable to fetch remote key")
	}

	key := new(vocab.PublicKey)
	act := AnonymousActor
	if err = jsonld.Unmarshal(body, &act); err != nil {
		if err = jsonld.Unmarshal(body, key); err != nil {
			return act, nil, err
		}

		// NOTE(marius): the SWICG document linked at the LoadActorFromIRIKey method mentions
		// that we can use both key.Owner or key.Controller, however we don't have Controller
		// in the PublicKey struct. We should probably change that.
		it, err := c.CtxLoadIRI(ctx, key.Owner)
		if err != nil {
			return act, key, err
		}

		_ = vocab.OnActor(it, func(actor *vocab.Actor) error {
			act = *actor
			return nil
		})
	} else {
		key = &act.PublicKey
	}

	return act, key, nil
}

// Verify reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (a *actorResolver) Verify(r *http.Request) (vocab.Actor, error) {
	if r == nil || r.Header == nil {
		return AnonymousActor, nil
	}

	logCtx := log.Ctx{}
	logCtx["req"] = fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI())

	method := "none"
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
	if typ == "" {
		return AnonymousActor, nil
	}

	switch typ {
	case "Bearer":
		method = "OAuth2"
		ol := oauthLoader(*a)
		return ol.Verify(r)
	case "Signature":
		method = "HTTP-Signature"
		kl := keyLoader(*a)
		return kl.Verify(r)
	}

	return AnonymousActor, errors.Unauthorizedf("Unauthorized").Challenge(method)
}

// LoadActorFromRequest reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (c *config) LoadActorFromRequest(r *http.Request, toIgnore ...vocab.IRI) (vocab.Actor, error) {
	// NOTE(marius): if the storage is nil, we can still use the remote client in the load function
	var st oauthStore
	if c.st == nil {
		return AnonymousActor, errors.Newf("invalid storage")
	}
	ar := Resolver(c.c,
		ConfigWithLogger(c.logFn), ConfigWithStorage(st), ConfigWithLocalIRIFn(c.iriIsLocal),
		ConfigWithIgnoreList(toIgnore...),
	)

	return ar.Verify(r)
}
