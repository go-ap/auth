package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-fed/httpsig"
	"github.com/openshift/osin"
	"golang.org/x/oauth2"
)

type oauthLoader config

// OAuth2
func OAuth2(cl Client, initFns ...ConfigInitFn) ActorVerifier {
	ol := oauthLoader(Config(cl, initFns...))
	return &ol
}

func (k *oauthLoader) Verify(r *http.Request) (vocab.Actor, error) {
	act := AnonymousActor
	bearer := osin.CheckBearerAuth(r)
	if bearer == nil {
		return act, errors.BadRequestf("could not load bearer token from request")
	}
	dat, err := k.st.LoadAccess(bearer.Code)
	if err != nil {
		return act, err
	}
	if dat == nil || dat.UserData == nil {
		return act, errors.NotFoundf("unable to load bearer")
	}
	if iri, err := assertToBytes(dat.UserData); err == nil {
		it, err := k.st.Load(vocab.IRI(iri))
		if err != nil {
			return act, unauthorized(err)
		}
		if vocab.IsNil(it) {
			return act, unauthorized(err)
		}
		if it, err = firstOrItem(it); err != nil {
			return act, unauthorized(err)
		}
		err = vocab.OnActor(it, func(actor *vocab.Actor) error {
			act = *actor
			return nil
		})
		if err != nil {
			return act, unauthorized(err)
		}
	} else {
		return act, errors.Unauthorizedf("unable to load from bearer")
	}
	return act, nil
}

var AnonymousActor = vocab.Actor{
	ID:   vocab.PublicNS,
	Type: vocab.ActorType,
	Name: vocab.DefaultNaturalLanguage("Anonymous"),
}

// readStore
type readStore interface {
	// Load returns an Item or an ItemCollection from an IRI
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
}

type oauthStore interface {
	readStore
	LoadAccess(token string) (*osin.AccessData, error)
}

func LoadActorFromOAuthToken(storage oauthStore, tok *oauth2.Token) (vocab.Actor, error) {
	var acc = AnonymousActor
	dat, err := storage.LoadAccess(tok.AccessToken)
	if err != nil {
		return acc, err
	}
	if dat == nil || dat.UserData == nil {
		return acc, errors.NotFoundf("unable to load bearer")
	}
	if iri, err := assertToBytes(dat.UserData); err == nil {
		it, err := storage.Load(vocab.IRI(iri))
		if err != nil {
			return acc, unauthorized(err)
		}
		if vocab.IsNil(it) {
			return acc, unauthorized(err)
		}
		if it, err = firstOrItem(it); err != nil {
			return acc, unauthorized(err)
		}
		err = vocab.OnActor(it, func(act *vocab.Actor) error {
			acc = *act
			return nil
		})
		if err != nil {
			return acc, unauthorized(err)
		}
	}
	return acc, nil
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
	return errors.NewUnauthorized(err, "unable to validate actor from Bearer token")
}

func assertToBytes(in any) ([]byte, error) {
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

func compatibleVerifyAlgorithms(pubKey crypto.PublicKey) []httpsig.Algorithm {
	algos := make([]httpsig.Algorithm, 0)
	switch pubKey.(type) {
	case *rsa.PublicKey:
		algos = append(algos, httpsig.RSA_SHA256, httpsig.RSA_SHA512)
	case *ecdsa.PublicKey:
		algos = append(algos, httpsig.ECDSA_SHA512, httpsig.ECDSA_SHA256)
	case ed25519.PublicKey:
		algos = append(algos, httpsig.ED25519)
	}
	return algos
}

func getAuthorization(hdr string) (string, string) {
	pieces := strings.SplitN(hdr, " ", 2)
	if len(pieces) < 2 {
		return hdr, ""
	}
	return pieces[0], pieces[1]
}
