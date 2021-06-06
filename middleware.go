package auth

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	pub "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	st "github.com/go-ap/storage"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"github.com/spacemonkeygo/httpsig"
)

var AnonymousActor = pub.Actor{
	ID:   pub.PublicNS,
	Type: pub.ActorType,
	Name: pub.NaturalLanguageValues{
		pub.LangRefValue{
			Ref:   pub.NilLangRef,
			Value: pub.Content("Anonymous"),
		},
	},
}

type keyLoader struct {
	baseIRI string
	logFn   func(string, ...interface{})
	realm   string
	acc     pub.Actor
	l       st.ReadStore
	c       client.Basic
}

func loadFederatedActor(c client.Basic, id pub.IRI) (pub.Actor, error) {
	it, err := c.LoadIRI(id)
	if err != nil {
		return AnonymousActor, err
	}
	if acct, ok := it.(*pub.Actor); ok {
		return *acct, nil
	}
	if acct, ok := it.(pub.Actor); ok {
		return acct, nil
	}
	return AnonymousActor, nil
}

func validateLocalIRI(i pub.IRI) error {
	if strings.Contains(i.String(), "Config.BaseURL") {
		return nil
	}
	return errors.Newf("%s is not a local IRI", i)
}

func (k *keyLoader) GetKey(id string) interface{} {
	var err error

	iri := pub.IRI(id)
	u, err := iri.URL()
	if err != nil {
		return err
	}
	if u.Fragment != "main-key" {
		// invalid generated public key id
		k.logFn("missing key")
		return nil
	}

	if err := validateLocalIRI(iri); err == nil {
		ob, err := k.l.Load(iri)
		if err != nil || pub.IsNil(ob) {
			k.logFn("unable to find local account matching key id %s", iri)
			return nil
		}
		var actor pub.Item
		if ob.IsCollection() {
			pub.OnCollectionIntf(ob, func(col pub.CollectionInterface) error {
				actor = col.Collection().First()
				return nil
			})
		}
		pub.OnActor(actor, func(a *pub.Actor) error {
			k.acc = *a
			return nil
		})
	} else {
		// @todo(queue_support): this needs to be moved to using queues
		k.acc, err = loadFederatedActor(k.c, iri)
		if err != nil {
			k.logFn("unable to load federated account matching key id %s", iri)
			return nil
		}
	}

	obj, err := pub.ToActor(k.acc)
	if err != nil {
		k.logFn("unable to load actor %s", err)
		return nil
	}
	var pub crypto.PublicKey
	rawPem := obj.PublicKey.PublicKeyPem
	block, _ := pem.Decode([]byte(rawPem))
	if block == nil {
		k.logFn("failed to parse PEM block containing the public key")
		return nil
	}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		k.logFn("x509 error %s", err)
		return nil
	}
	return pub
}

type oauthLoader struct {
	logFn func(string, ...interface{})
	acc   pub.Actor
	s     osin.Storage
	l     st.ReadStore
}

func firstOrItem(it pub.Item) (pub.Item, error) {
	if it.IsCollection() {
		err := pub.OnCollectionIntf(it, func(col pub.CollectionInterface) error {
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
		it, err := k.l.Load(pub.IRI(iri))
		if err != nil {
			return unauthorized(err), ""
		}
		if pub.IsNil(it) {
			return unauthorized(err), ""
		}
		if it, err = firstOrItem(it); err != nil {
			return unauthorized(err), ""
		}
		err = pub.OnActor(it, func(act *pub.Actor) error {
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
	if getter.realm != "" {
		challengeParams = append(challengeParams, fmt.Sprintf("realm=%q", getter.realm))
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
func ActorContext(ctx context.Context) (pub.Actor, bool) {
	ctxVal := ctx.Value(ActorKey)
	if p, ok := ctxVal.(pub.Actor); ok {
		return p, ok
	}
	if p, ok := ctxVal.(*pub.Actor); ok {
		return *p, ok
	}
	return AnonymousActor, false
}

// LoadActorFromAuthHeader reads the Authorization header of an HTTP request and tries to decode it either pub
// an OAuth2 or HTTP Signatures:
//   For OAuth2 it tries to load the matching local actor and use it further in the processing logic
//   For HTTP Signatures it tries to load the federated actor and use it further in the processing logic
func (s *Server) LoadActorFromAuthHeader(r *http.Request) (pub.Actor, error) {
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
			getter := keyLoader{acc: acct, l: s.st, realm: r.URL.Host, c: s.cl}
			method = "httpSig"
			getter.logFn = s.l.WithFields(logrus.Fields{"from": method}).Debugf

			var v *httpsig.Verifier
			v, challenge = httpSignatureVerifier(&getter)
			if err = v.Verify(r); err == nil {
				acct = getter.acc
			}
		}
	}
	if err == nil {
		// TODO(marius): Add actor's host to the logging
		s.l.WithFields(logrus.Fields{
			"auth": method,
			"id":   acct.GetID(),
		}).Debug("loaded account from Authorization header")
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
