package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/httpsig"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

var AnonymousActor = vocab.Actor{
	ID:   vocab.PublicNS,
	Type: vocab.ActorType,
	Name: vocab.NaturalLanguageValues{
		vocab.LangRefValue{
			Ref:   vocab.NilLangRef,
			Value: vocab.Content("Anonymous"),
		},
	},
}

// ReadStore
type ReadStore interface {
	// Load returns an Item or an ItemCollection from an IRI
	Load(vocab.IRI) (vocab.Item, error)
}

type keyLoader struct {
	baseIRI string
	logFn   func(string, ...interface{})
	acc     vocab.Actor
	l       ReadStore
	c       client.Basic
}

func (k keyLoader) validateLocalIRI(i vocab.IRI) error {
	if i.Contains(vocab.IRI(k.baseIRI), true) {
		return nil
	}
	return errors.Newf("%s is not a local IRI", i)
}

func (k *keyLoader) GetKey(id string) (interface{}, error) {
	iri := vocab.IRI(id)
	u, err := iri.URL()
	if err != nil {
		return nil, err
	}
	if u.Fragment != "main-key" {
		return nil, errors.Newf("missing key")
	}

	var ob vocab.Item
	var loadFn func(vocab.IRI) (vocab.Item, error) = k.l.Load

	if !iri.Contains(vocab.IRI(k.baseIRI), true) {
		loadFn = k.c.LoadIRI
	}

	if ob, err = loadFn(iri); err != nil {
		return nil, errors.NewNotFound(err, "unable to find actor matching key id %s", iri)
	}
	if vocab.IsNil(ob) {
		return nil, errors.NotFoundf("unable to find actor matching key id %s", iri)
	}
	err = vocab.OnActor(ob, func(a *vocab.Actor) error {
		k.acc = *a
		return nil
	})
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(k.acc.PublicKey.PublicKeyPem))
	if block == nil {
		return nil, errors.Newf("failed to parse PEM block containing the public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

type oauthLoader struct {
	logFn func(string, ...interface{})
	acc   vocab.Actor
	s     osin.Storage
	l     ReadStore
}

func firstOrItem(it vocab.Item) (vocab.Item, error) {
	if it.IsCollection() {
		err := vocab.OnCollectionIntf(it, func(col vocab.CollectionInterface) error {
			it = col.Collection().First()
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return it, nil
}

func unauthorized(err error) error {
	return errors.NewUnauthorized(err, "Unable to validate actor from Bearer token")
}

func assertToBytes(in interface{}) ([]byte, error) {
	var ok bool
	var data string
	if in == nil {
		return nil, nil
	} else if data, ok = in.(string); ok {
		return []byte(data), nil
	} else if byt, ok := in.([]byte); ok {
		return byt, nil
	} else if byt, ok := in.(json.RawMessage); ok {
		return byt, nil
	} else if str, ok := in.(fmt.Stringer); ok {
		return []byte(str.String()), nil
	}
	return nil, errors.Errorf(`Could not assert "%v" to string`, in)
}

func (k *oauthLoader) Verify(r *http.Request) (error, string) {
	bearer := osin.CheckBearerAuth(r)
	if bearer == nil {
		return errors.BadRequestf("could not load bearer token from request"), ""
	}
	dat, err := k.s.LoadAccess(bearer.Code)
	if err != nil {
		return err, ""
	}
	if dat == nil || dat.UserData == nil {
		return errors.NotFoundf("unable to load bearer"), ""
	}
	if iri, err := assertToBytes(dat.UserData); err == nil {
		it, err := k.l.Load(vocab.IRI(iri))
		if err != nil {
			return unauthorized(err), ""
		}
		if vocab.IsNil(it) {
			return unauthorized(err), ""
		}
		if it, err = firstOrItem(it); err != nil {
			return unauthorized(err), ""
		}
		err = vocab.OnActor(it, func(act *vocab.Actor) error {
			k.acc = *act
			return nil
		})
		if err != nil {
			return unauthorized(err), ""
		}
	} else {
		return errors.Unauthorizedf("unable to load from bearer"), ""
	}
	return nil, ""
}

func httpSignatureVerifier(getter *keyLoader) (*httpsig.Verifier, string) {
	v := httpsig.NewVerifier(getter)
	v.SetRequiredHeaders([]string{"(request-target)", "host", "date"})

	var challengeParams []string
	if getter.baseIRI != "" {
		challengeParams = append(challengeParams, fmt.Sprintf("realm=%q", getter.baseIRI))
	}
	if headers := v.RequiredHeaders(); len(headers) > 0 {
		challengeParams = append(challengeParams, fmt.Sprintf("headers=%q", strings.Join(headers, " ")))
	}

	challenge := "Signature"
	if len(challengeParams) > 0 {
		challenge += fmt.Sprintf(" %s", strings.Join(challengeParams, ", "))
	}
	return v, challenge
}

// CtxtKey
type CtxtKey string

// ActorKey
var ActorKey = CtxtKey("__actor")

// ActorContext
func ActorContext(ctx context.Context) (vocab.Actor, bool) {
	ctxVal := ctx.Value(ActorKey)
	if p, ok := ctxVal.(vocab.Actor); ok {
		return p, ok
	}
	if p, ok := ctxVal.(*vocab.Actor); ok {
		return *p, ok
	}
	return AnonymousActor, false
}

// LoadActorFromAuthHeader reads the Authorization header of an HTTP request and tries to decode it either vocab
// an OAuth2 or HTTP Signatures:
//   For OAuth2 it tries to load the matching local actor and use it further in the processing logic
//   For HTTP Signatures it tries to load the federated actor and use it further in the processing logic
func (s *Server) LoadActorFromAuthHeader(r *http.Request) (vocab.Actor, error) {
	acct := AnonymousActor
	var challenge string
	var err error
	method := "none"

	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.Contains(auth, "Bearer") {
			// check OAuth2(plain) bearer if present
			method = "oauth2"
			v := oauthLoader{acc: acct, s: s.Server.Storage, l: s.st}
			v.logFn = s.l.WithFields(logrus.Fields{"from": method}).Debugf
			if err, challenge = v.Verify(r); err == nil {
				acct = v.acc
			}
		}
		if strings.Contains(auth, "Signature") {
			// verify http-signature if present
			getter := keyLoader{acc: acct, l: s.st, baseIRI: s.baseURL, c: s.cl}
			method = "httpSig"
			getter.logFn = s.l.WithFields(logrus.Fields{"from": method}).Debugf

			var v *httpsig.Verifier
			v, challenge = httpSignatureVerifier(&getter)
			if _, err = v.Verify(r); err == nil {
				acct = getter.acc
			}
		}
	}
	if err == nil {
		// TODO(marius): Add actor's host to the logging
		if !acct.GetID().Equals(AnonymousActor.GetID(), true) {
			s.l.WithFields(logrus.Fields{
				"auth": method,
				"id":   acct.GetID(),
			}).Debug("loaded account from Authorization header")
		}
		return acct, nil
	}
	// TODO(marius): fix this challenge passing
	err = errors.NewUnauthorized(err, "Unauthorized").Challenge(challenge)
	errContext := logrus.Fields{
		"auth":      r.Header.Get("Authorization"),
		"req":       fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI()),
		"err":       err.Error(),
		"challenge": challenge,
	}
	id := acct.GetID()
	if id.IsValid() {
		errContext["id"] = id
	}
	if challenge != "" {
		errContext["challenge"] = challenge
	}
	s.l.WithFields(errContext).Warn("Invalid HTTP Authorization")
	return acct, err
}
