package auth

import (
	"fmt"
	"net/http"
	"strings"

	log "git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
)

// actorResolver is a used for resolving actors either in local storage or remotely
type actorResolver struct {
	baseURL    string
	iriIsLocal func(vocab.IRI) bool
	c          client.Basic
	st         readStore
	l          log.Logger
}

func ClientResolver(cl client.Basic, initFns ...func(*actorResolver)) *actorResolver {
	s := &actorResolver{c: cl}
	for _, fn := range initFns {
		fn(s)
	}
	return s
}

func SolverWithLocalIRIFn(fn func(vocab.IRI) bool) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.iriIsLocal = fn
	}
}
func SolverWithLogger(l log.Logger) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.l = l
	}
}

func SolverWithStorage(s oauthStore) func(*actorResolver) {
	return func(resolver *actorResolver) {
		resolver.st = s
	}
}

func (a actorResolver) Load(iri vocab.IRI) (*vocab.Actor, error) {
	var (
		actor vocab.Item
		err   error
	)
	if a.st == nil || a.iriIsLocal(iri) {
		actor, err = a.st.Load(iri)
	} else {
		actor, err = a.c.LoadIRI(iri)
	}
	if err != nil {
		return &AnonymousActor, err
	}
	return vocab.ToActor(actor)
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
	if auth := r.Header.Get("Signature"); auth != "" {
		header = auth

		// verify HTTP-Signature if present
		getter := keyLoader{acc: &acct, loadFn: a.Load}
		logCtx["header"] = strings.Replace(header, auth, mask.S(auth).String(), 1)
		method = "HTTP-Sig"
		getter.logFn = a.l.WithContext(log.Ctx{"from": method}).Debugf

		if err = verifyHTTPSignature(r, &getter); err == nil {
			acct = *getter.acc
		}
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		header = auth
		typ, auth := getAuthorization(header)
		if typ == "" {
			return acct, nil
		}

		if typ == "Bearer" {
			// check OAuth2(plain) Bearer if present
			method = "OAuth2"
			storage, ok := a.st.(oauthStore)
			if ok {
				logCtx["header"] = strings.Replace(header, auth, mask.S(auth).String(), 1)
				v := oauthLoader{acc: &acct, s: storage}
				v.logFn = a.l.WithContext(log.Ctx{"from": method}).Debugf
				if err, challenge = v.Verify(r); err == nil {
					acct = *v.acc
				}
			}
		}
	}

	if header == "" {
		return acct, nil
	}
	if err != nil {
		// TODO(marius): fix this challenge passing
		err = errors.NewUnauthorized(err, "Unauthorized").Challenge(challenge)
		logCtx["err"] = err.Error()
		if id := acct.GetID(); id.IsValid() {
			logCtx["id"] = id
		}
		if challenge != "" {
			logCtx["challenge"] = challenge
		}
		a.l.WithContext(logCtx).Warnf("Invalid HTTP Authorization")
		return acct, err
	}
	// TODO(marius): Add actor'a host to the logging
	if !acct.GetID().Equals(AnonymousActor.GetID(), true) {
		u, _ := acct.GetID().URL()
		logCtx["auth"] = method
		logCtx["instance"] = u.Host
		logCtx["id"] = acct.GetID()
		logCtx["type"] = acct.GetType()
		logCtx["name"] = acct.Name.String()
		a.l.WithContext(logCtx).Debugf("loaded Actor from Authorization header")
	}
	return acct, nil
}
