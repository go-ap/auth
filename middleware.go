package auth

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/go-ap/activitypub"
	"github.com/go-ap/activitypub/client"
	as "github.com/go-ap/activitystreams"
	"github.com/go-ap/errors"
	st "github.com/go-ap/storage"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"github.com/spacemonkeygo/httpsig"
	"net/http"
	"strings"
)

const ActivityStreamsPublicNS = as.IRI("https://www.w3.org/ns/activitystreams#Public")

var AnonymousActor = Person{
	Person: activitypub.Person{
		Parent: as.Person{
			ID:   as.ObjectID(ActivityStreamsPublicNS),
			Type: as.PersonType,
			Name: as.NaturalLanguageValues{
				as.LangRefValue{
					Ref:   as.NilLangRef,
					Value: "Anonymous",
				},
			},
		},
	},
}

type keyLoader struct {
	baseIRI string
	logFn   func(string, ...interface{})
	realm   string
	acc     Person
	l       st.ActorLoader
	c       client.Client
}

func loadFederatedActor(c client.Client, id as.IRI) (Person, error) {
	it, err := c.LoadIRI(id)
	if err != nil {
		return AnonymousActor, err
	}
	if acct, ok := it.(*Person); ok {
		return *acct, nil
	}
	if acct, ok := it.(Person); ok {
		return acct, nil
	}
	return AnonymousActor, nil
}

func validateLocalIRI(i as.IRI) error {
	if strings.Contains(i.String(), "Config.BaseURL") {
		return nil
	}
	return errors.Newf("%s is not a local IRI", i)
}

func (k *keyLoader) GetKey(id string) interface{} {
	var err error

	iri := as.IRI(id)
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
		actors, cnt, err := k.l.LoadActors(iri)
		if err != nil || cnt == 0 {
			k.logFn("unable to find local account matching key id %s", iri)
			return nil
		}
		actor := actors.First()
		if acct, err := ToPerson(actor); err == nil {
			k.acc = *acct
		}
	} else {
		// @todo(queue_support): this needs to be moved to using queues
		k.acc, err = loadFederatedActor(k.c, iri)
		if err != nil {
			k.logFn("unable to load federated account matching key id %s", iri)
			return nil
		}
	}

	obj, err := ToPerson(k.acc)
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
	acc   Person
	s     *osin.Server
}

func (k *oauthLoader) Verify(r *http.Request) (error, string) {
	bearer := osin.CheckBearerAuth(r)
	dat, err := k.s.Storage.LoadAccess(bearer.Code)
	if err != nil {
		return err, ""
	}
	if b, ok := dat.UserData.(json.RawMessage); ok {
		if err := json.Unmarshal(b, &k.acc); err != nil {
			return err, ""
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
func ActorContext(ctx context.Context) (Person, bool) {
	ctxVal := ctx.Value(ActorKey)
	if p, ok := ctxVal.(Person); ok {
		return p, ok
	}
	if p, ok := ctxVal.(*Person); ok {
		return *p, ok
	}
	return AnonymousActor, false
}

// LoadActorFromAuthHeader reads the Authorization header of an HTTP request and tries to decode it either as
// an OAuth2 or HTTP Signatures:
//   For OAuth2 it tries to load the matching local Actor and use it further in the processing logic
//   For HTTP Signatures it tries to load the federated Actor and use it further in the processing logic
func (s *Server) LoadActorFromAuthHeader(r *http.Request) (as.Actor, error) {
	acct := AnonymousActor
	if auth := r.Header.Get("Authorization"); auth != "" {
		var err error
		var challenge string
		method := "none"
		if strings.Contains(auth, "Bearer") {
			// check OAuth2 bearer if present
			method = "oauth2"
			v := oauthLoader{acc: acct, s: s.os}
			v.logFn = s.l.WithFields(logrus.Fields{"from": method}).Debugf
			if err, challenge = v.Verify(r); err == nil {
				acct = v.acc
			}
		}
		if strings.Contains(auth, "Signature") {
			// only verify http-signature if present
			getter := keyLoader{acc: acct, l: s.loader, realm: r.URL.Host, c: s.cl}
			method = "httpSig"
			getter.logFn = s.l.WithFields(logrus.Fields{"from": method}).Debugf

			var v *httpsig.Verifier
			v, challenge = httpSignatureVerifier(&getter)
			if err = v.Verify(r); err == nil {
				acct = getter.acc
			}
		}
		if err != nil {
			// TODO(marius): fix this challenge passing
			err = errors.NewUnauthorized(err, "").Challenge(challenge)
			s.l.WithFields(logrus.Fields{
				"id":        acct.GetID(),
				"auth":      r.Header.Get("Authorization"),
				"req":       fmt.Sprintf("%s:%s", r.Method, r.URL.RequestURI()),
				"err":       err,
				"challenge": challenge,
			}).Warn("Invalid HTTP Authorization")
			return acct, err
		} else {
			// TODO(marius): Add actor's host to the logging
			s.l.WithFields(logrus.Fields{
				"auth": method,
				"id":   acct.GetID(),
			}).Debug("loaded account from Authorization header")
		}
	}
	return acct, nil
}
