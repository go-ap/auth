package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"

	log "git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
)

type Client interface {
	CtxGet(context.Context, string) (*http.Response, error)
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
type actorResolver struct {
	config
	act *vocab.Actor
}

// ActorVerifier verifies if a [http.Request] contains information about an ActivityPub [vocab.Actor]
// that has operated it.
type ActorVerifier interface {
	// Verify validates a request for the existence of an authorized ActivityPub [vocab.Actor] that has
	// operated it.
	Verify(*http.Request) (vocab.Actor, error)
}

func Resolver(cl Client, initFns ...SolverInitFn) ActorVerifier {
	c := config{c: cl}
	for _, fn := range initFns {
		fn(&c)
	}
	s := actorResolver{config: c}
	return &s
}

type SolverInitFn = func(*config)

func SolverWithIgnoreList(iris ...vocab.IRI) SolverInitFn {
	return func(conf *config) {
		conf.ignore = iris
	}
}

func SolverWithLocalIRIFn(fn func(vocab.IRI) bool) SolverInitFn {
	return func(conf *config) {
		conf.iriIsLocal = fn
	}
}

func SolverWithLogger(l LoggerFn) SolverInitFn {
	return func(conf *config) {
		conf.logFn = l
	}
}

func SolverWithStorage(s oauthStore) SolverInitFn {
	return func(conf *config) {
		conf.st = s
	}
}

// LoadRemoteKey fetches a remote Public Key and returns it's owner.
func LoadRemoteKey(ctx context.Context, c Client, iri vocab.IRI) (*vocab.Actor, *vocab.PublicKey, error) {
	resp, err := c.CtxGet(ctx, iri.String())
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, errors.NotFoundf("unable to load iri %s", iri)
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusGone, http.StatusNotModified:
		// OK
	default:
		return nil, nil, errors.NewFromStatus(resp.StatusCode, "unable to fetch remote key")
	}

	key := new(vocab.PublicKey)
	act := new(vocab.Actor)
	if err = jsonld.Unmarshal(body, act); err != nil {
		if err = jsonld.Unmarshal(body, key); err != nil {
			return nil, nil, err
		}

		// NOTE(marius): the SWICG document linked at the LoadActorFromIRIKey method mentions
		// that we can use both key.Owner or key.Controller, however we don't have Controller
		// in the PublicKey struct. We should probably change that.
		it, err := c.CtxLoadIRI(ctx, key.Owner)
		if err != nil {
			return nil, key, err
		}

		if act, err = vocab.ToActor(it); err != nil {
			return nil, key, err
		}
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
		ol := oauthLoader{config: a.config}
		return ol.Verify(r)
	case "Signature":
		method = "HTTP-Signature"
		kl := keyLoader{act: a.act, config: a.config}
		return kl.Verify(r)
	}

	return AnonymousActor, errors.Unauthorizedf("Unauthorized").Challenge(method)
}
