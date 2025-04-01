package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
)

type Client interface {
	CtxGet(context.Context, string) (*http.Response, error)
	CtxLoadIRI(context.Context, vocab.IRI) (vocab.Item, error)
}

// actorResolver is a used for resolving actors either in local storage or remotely
type actorResolver struct {
	baseURL    string
	iriIsLocal func(vocab.IRI) bool
	ignore     vocab.IRIs
	c          Client
	st         readStore
	l          LoggerFn
}

func ClientResolver(cl Client, initFns ...func(*actorResolver)) actorResolver {
	s := actorResolver{c: cl}
	for _, fn := range initFns {
		fn(&s)
	}
	return s
}

func SolverWithIgnoreList(iris ...vocab.IRI) func(resolver *actorResolver) {
	return func(resolver *actorResolver) {
		resolver.ignore = iris
	}
}

func SolverWithLocalIRIFn(fn func(vocab.IRI) bool) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.iriIsLocal = fn
	}
}

func SolverWithLogger(l LoggerFn) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.l = l
	}
}

func SolverWithStorage(s oauthStore) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.st = s
	}
}

// iriIsIgnored this checks if the incoming iri belongs to any of the hosts/instances/iris in the
// ignored list.
func (a actorResolver) iriIsIgnored(iri vocab.IRI) bool {
	for _, i := range a.ignore {
		if iri.Contains(i, false) {
			return true
		}
	}
	return false
}

func (a actorResolver) loadFromStorage(iri vocab.IRI) (*vocab.Actor, *vocab.PublicKey, error) {
	if a.st == nil {
		return &AnonymousActor, nil, errors.Newf("nil storage")
	}

	u, err := iri.URL()
	if err != nil {
		return &AnonymousActor, nil, errors.Annotatef(err, "invalid URL to load")
	}
	if u.Fragment != "" {
		u.Fragment = ""
		iri = vocab.IRI(u.String())
	}

	// NOTE(marius): in the case of the locally saved actors, we don't have *YET* public keys stored
	// as independent objects.
	// Therefore, there's no need to check if the IRI belongs to a Key object, and if that's the case
	// then dereference the owner, as we do in the remote case.
	it, err := a.st.Load(iri)
	if err != nil {
		return &AnonymousActor, nil, err
	}

	act, err := vocab.ToActor(it)
	if err != nil {
		return act, nil, err
	}

	return act, &act.PublicKey, nil
}

// LoadActorFromKeyIRI retrieves the public key and tries to dereference the [vocab.Actor] it belongs
// to.
// The basic algorithm has been described here:
// https://swicg.github.io/activitypub-http-signature/#how-to-obtain-a-signature-s-public-key
func (a actorResolver) LoadActorFromKeyIRI(iri vocab.IRI) (*vocab.Actor, *vocab.PublicKey, error) {
	var err error
	if a.st == nil && a.c == nil {
		return &AnonymousActor, nil, nil
	}
	if a.iriIsIgnored(iri) {
		return &AnonymousActor, nil, errors.Forbiddenf("actor is blocked")
	}

	act := &AnonymousActor
	var key *vocab.PublicKey

	// NOTE(marius): first try to load from local storage
	act, key, err = a.loadFromStorage(iri)
	if err == nil && key != nil {
		return act, key, nil
	}

	if a.c == nil {
		return &AnonymousActor, nil, errors.Newf("nil client")
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), DefaultKeyWaitLoadTime)
	defer cancelFn()

	// NOTE(marius): then we try to load the IRI as a public key
	act, key, err = a.LoadRemoteKey(ctx, iri)
	if err == nil && key != nil {
		return act, key, nil
	}

	// NOTE(marius): if everything fails we try to load the IRI as an actor IRI
	it, err := a.c.CtxLoadIRI(ctx, iri)
	if err != nil {
		return &AnonymousActor, nil, err
	}

	err = vocab.OnActor(it, func(a *vocab.Actor) error {
		act = a
		key = &a.PublicKey
		return nil
	})

	// TODO(marius): check that act.PublicKey matches the key we just loaded if it exists.
	return act, key, err
}

var DefaultKeyWaitLoadTime = 2 * time.Second

// LoadRemoteKey fetches a remote Public Key and returns it's owner.
func (a actorResolver) LoadRemoteKey(ctx context.Context, iri vocab.IRI) (*vocab.Actor, *vocab.PublicKey, error) {
	resp, err := a.c.CtxGet(ctx, iri.String())
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
		it, err := a.c.CtxLoadIRI(ctx, key.Owner)
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

// LoadActorFromRequest reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (a actorResolver) LoadActorFromRequest(r *http.Request) (vocab.Actor, error) {
	acct := AnonymousActor
	var challenge string
	var err error
	method := "none"
	if r == nil || r.Header == nil {
		return acct, nil
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
	if typ == "" {
		return acct, nil
	}

	switch typ {
	case "Bearer":
		// check OAuth2(plain) Bearer if present
		method = "OAuth2"
		storage, ok := a.st.(oauthStore)
		if ok {
			v := oauthLoader{acc: &acct, s: storage}
			v.logFn = a.l //.WithContext(log.Ctx{"from": method}).Debugf
			if err, challenge = v.Verify(r); err == nil {
				acct = *v.acc
			}
		}
	case "Signature":
		// verify HTTP-Signature if present
		getter := keyLoader{acc: &acct, loadActorFromKeyFn: a.LoadActorFromKeyIRI}
		method = "HTTP-Sig"
		getter.logFn = a.l

		if err = verifyHTTPSignature(r, &getter); err == nil {
			acct = *getter.acc
		}
	}

	if err != nil {
		// TODO(marius): fix this challenge passing
		err = errors.NewUnauthorized(err, "Unauthorized").Challenge(challenge)
		logCtx["err"] = err.Error()
		logCtx["header"] = strings.Replace(header, auth, mask.S(auth).String(), 1)
		if id := acct.GetID(); id.IsValid() {
			logCtx["id"] = id
		}
		if challenge != "" {
			logCtx["challenge"] = challenge
		}
		a.l(logCtx, "Invalid HTTP Authorization")
		return acct, err
	}

	if !acct.GetID().Equals(AnonymousActor.GetID(), true) {
		logCtx["auth"] = method
		logCtx["id"] = acct.GetID()
		logCtx["type"] = acct.GetType()
		if name := vocab.NameOf(acct); len(name) > 0 {
			logCtx["name"] = name
		}
		if u, err := acct.GetID().URL(); err == nil {
			logCtx["instance"] = u.Host
		}
		a.l(logCtx, "Loaded Actor from Authorization header")
	}
	return acct, nil
}
