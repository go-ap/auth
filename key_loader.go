package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-fed/httpsig"
)

type keyLoader config

// HTTPSignatureResolver returns a HTTP-Signature validator for loading f
func HTTPSignatureResolver(cl Client, initFns ...SolverInitFn) ActorVerifier {
	c := config{c: cl}
	for _, fn := range initFns {
		fn(&c)
	}
	kl := keyLoader(c)
	return &kl
}

func toCryptoPublicKey(key vocab.PublicKey) (crypto.PublicKey, error) {
	pubBytes, _ := pem.Decode([]byte(key.PublicKeyPem))
	if pubBytes == nil {
		return nil, errors.Newf("unable to decode PEM payload for public key")
	}
	pk, err := x509.ParsePKIXPublicKey(pubBytes.Bytes)
	if pk != nil {
		return pk, nil
	}
	pk, err = x509.ParsePKCS1PublicKey(pubBytes.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pk.(type) {
	case *rsa.PublicKey:
		return pub, nil
	case *ecdsa.PublicKey:
		return pub, nil
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, errors.Newf("invalid public key type %T", pk)
	}
}

func (k *keyLoader) GetKey(id string) (vocab.Actor, crypto.PublicKey, error) {
	iri := vocab.IRI(id)
	_, err := iri.URL()
	if err != nil {
		return AnonymousActor, nil, err
	}

	k.logFn(nil, "Loading Actor from Key IRI: %s", iri)
	act, key, err := k.LoadActorFromKeyIRI(iri)
	if err != nil && !errors.IsNotModified(err) {
		if errors.IsForbidden(err) {
			return act, nil, err
		}
		return act, nil, errors.NewNotFound(err, "unable to find actor matching key id %s", iri)
	}
	if vocab.IsNil(act) {
		return act, nil, errors.NotFoundf("unable to find actor matching key id %s", iri)
	}
	if !vocab.IsObject(act) {
		return act, nil, errors.NotFoundf("unable to load actor matching key id %s, received %T", iri, act)
	}

	if key == nil {
		return act, nil, errors.NotFoundf("invalid key loaded %s for actor %s", iri, act.ID)
	}

	pub, err := toCryptoPublicKey(*key)
	return act, pub, err
}

func (k *keyLoader) Verify(r *http.Request) (vocab.Actor, error) {
	v, err := httpsig.NewVerifier(r)
	if err != nil {
		return AnonymousActor, errors.Annotatef(err, "unable to initialize HTTP Signatures verifier")
	}
	verifyFn := func(pubKey *vocab.PublicKey) error {
		pk, err := toCryptoPublicKey(*pubKey)
		if err != nil {
			return errors.Annotatef(err, "invalid public key")
		}

		algs := compatibleVerifyAlgorithms(pk)
		errs := make([]error, 0, len(algs))
		for _, algo := range algs {
			if err = v.Verify(pk, algo); err == nil {
				return nil
			}
			errs = append(errs, errors.Annotatef(err, "failed %s", algo))
		}
		return errors.Join(errs...)
	}

	// NOTE(marius): we first try to verify with the copy of the key stored locally if it exists.
	actor, key, _ := k.loadLocalKey(vocab.IRI(v.KeyId()))
	if key != nil {
		if err = verifyFn(key); err == nil {
			return actor, nil
		}
	}

	// NOTE(marius): if local verification fails, we try to fetch a fresh copy of the key and try again.
	actor, key, err = k.loadRemoteKey(vocab.IRI(v.KeyId()))
	if err != nil {
		return AnonymousActor, errors.Annotatef(err, "unable to load public key based on signature")
	}
	if err = verifyFn(key); err == nil {
		return actor, nil
	}
	return AnonymousActor, errors.Annotatef(err, "unable to verify HTTP Signature with any of the attempted algorithms")
}

var DefaultKeyWaitLoadTime = 2 * time.Second

// LoadActorFromKeyIRI retrieves the public key and tries to dereference the [vocab.Actor] it belongs
// to.
// The basic algorithm has been described here:
// https://swicg.github.io/activitypub-http-signature/#how-to-obtain-a-signature-s-public-key
func (k *keyLoader) LoadActorFromKeyIRI(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	var err error
	if k.st == nil && k.c == nil {
		return AnonymousActor, nil, nil
	}
	if k.iriIsIgnored(iri) {
		return AnonymousActor, nil, errors.Forbiddenf("actor is blocked")
	}

	act := AnonymousActor
	var key *vocab.PublicKey

	// NOTE(marius): first try to load from local storage
	act, key, err = k.loadLocalKey(iri)
	if err == nil && key != nil {
		k.logFn(lw.Ctx{"key": keyS(key.PublicKeyPem), "iri": act.ID}, "found local key and actor")
		return act, key, nil
	}
	return k.loadRemoteKey(iri)
}

func (k *keyLoader) loadRemoteKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.c == nil {
		return AnonymousActor, nil, errors.Newf("nil client")
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), DefaultKeyWaitLoadTime)
	defer cancelFn()

	// NOTE(marius): then we try to load the IRI as a public key
	act, key, err := LoadRemoteKey(ctx, k.c, iri)
	if err == nil && key != nil {
		return act, key, nil
	}

	// NOTE(marius): if everything fails we try to load the IRI as an actor IRI
	it, err := k.c.CtxLoadIRI(ctx, iri)
	if err != nil {
		return AnonymousActor, nil, err
	}

	err = vocab.OnActor(it, func(a *vocab.Actor) error {
		act = *a
		key = &a.PublicKey
		return nil
	})

	k.logFn(lw.Ctx{"key": keyS(key.PublicKeyPem), "iri": act.ID}, "loaded remote public key and actor")
	// TODO(marius): check that act.PublicKey matches the key we just loaded if it exists.
	return act, key, err
}

func keyS(kk string) string {
	return strings.ReplaceAll(kk, "\n", "")
}

// iriIsIgnored this checks if the incoming iri belongs to any of the hosts/instances/iris in the
// ignored list.
func (k *keyLoader) iriIsIgnored(iri vocab.IRI) bool {
	for _, i := range k.ignore {
		if iri.Contains(i, false) {
			return true
		}
	}
	return false
}

func (k *keyLoader) loadLocalKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.st == nil {
		return AnonymousActor, nil, errors.Newf("invalid storage for key loader")
	}

	act := AnonymousActor
	u, err := iri.URL()
	if err != nil {
		return act, nil, errors.Annotatef(err, "invalid URL to load")
	}
	if u.Fragment != "" {
		u.Fragment = ""
		iri = vocab.IRI(u.String())
	}

	// NOTE(marius): in the case of the locally saved actors, we don't have *YET* public keys stored
	// as independent objects.
	// Therefore, there's no need to check if the IRI belongs to a Key object, and if that's the case
	// then dereference the owner, as we do in the remote case.
	it, err := k.st.Load(iri)
	if err != nil {
		return act, nil, err
	}

	var key *vocab.PublicKey
	err = vocab.OnActor(it, func(a *vocab.Actor) error {
		act = *a
		key = &a.PublicKey
		return nil
	})

	return act, key, nil
}
