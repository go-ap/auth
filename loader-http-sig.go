package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	draft "github.com/go-fed/httpsig"
)

type keyLoader config

// HTTPSignature returns a HTTP-Signature validator for loading f
func HTTPSignature(cl apClient, initFns ...InitFn) keyLoader {
	return keyLoader(Config(cl, initFns...))
}

func toCryptoPublicKey(key vocab.PublicKey) (crypto.PublicKey, error) {
	pubBytes, _ := pem.Decode([]byte(key.PublicKeyPem))
	if pubBytes == nil {
		return nil, errors.Newf("unable to decode PEM payload for public key")
	}
	pk, _ := x509.ParsePKIXPublicKey(pubBytes.Bytes)
	if pk != nil {
		return pk, nil
	}
	return x509.ParsePKCS1PublicKey(pubBytes.Bytes)
}

func (k keyLoader) GetKey(id string) (vocab.Actor, crypto.PublicKey, error) {
	iri := vocab.IRI(id)
	_, err := iri.URL()
	if err != nil {
		return AnonymousActor, nil, err
	}

	k.l.WithContext(lw.Ctx{"iri": iri}).Debugf("loading Actor from Key IRI")
	act, key, err := k.LoadActorFromKeyIRI(iri)
	if err != nil && !errors.IsNotModified(err) {
		if errors.IsForbidden(err) {
			return act, nil, err
		}
		return act, nil, errors.NewNotFound(err, "unable to find actor matching key id %s", iri)
	}
	if !vocab.IsObject(act) {
		return act, nil, errors.NotFoundf("unable to load actor matching key id %s, received %T", iri, act)
	}

	var pub crypto.PublicKey
	if key != nil {
		pub, err = toCryptoPublicKey(*key)
	}
	return act, pub, err
}

func (k keyLoader) loadKey(keyID string) (vocab.Actor, *vocab.PublicKey, error) {
	// NOTE(marius): we first try to verify with the copy of the key stored locally if it exists.
	actor, key, _ := k.loadLocalKey(vocab.IRI(keyID))
	if key != nil {
		return actor, key, nil
	}

	// NOTE(marius): if local verification fails, we try to fetch a fresh copy of the key and try again.
	return k.loadRemoteKey(vocab.IRI(keyID))
}

func (k keyLoader) VerifyDraftSignature(r *http.Request) (vocab.Actor, error) {
	v, err := draft.NewVerifier(r)
	if err != nil {
		return AnonymousActor, errors.NewBadRequest(err, "unable to initialize HTTP Signatures verifier")
	}

	draftVerifyFn := func(pubKey *vocab.PublicKey) error {
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

	actor, key, err := k.loadKey(v.KeyId())
	if err != nil {
		return AnonymousActor, errors.Annotatef(err, "unable to load public key based on signature")
	}

	if err = draftVerifyFn(key); err != nil {
		return AnonymousActor, err
	}
	return actor, nil
}

func (k keyLoader) Verify(r *http.Request) (vocab.Actor, error) {
	if k.st == nil {
		return AnonymousActor, errInvalidStorage
	}
	if r == nil || r.Header == nil {
		return AnonymousActor, nil
	}

	if sigInput := r.Header.Get("Signature-Input"); sigInput != "" {
		actor, err := k.VerifyRFCSignature(r)
		if err != nil {
			return AnonymousActor, err
		}
		return actor, nil
	}

	actor, err := k.VerifyDraftSignature(r)
	if err != nil {
		return AnonymousActor, err
	}
	return actor, nil
}

var DefaultKeyWaitLoadTime = 4 * time.Second

// LoadActorFromKeyIRI retrieves the public key and tries to dereference the [vocab.Actor] it belongs
// to.
// The basic algorithm has been described here:
// https://swicg.github.io/activitypub-http-signature/#how-to-obtain-a-signature-s-public-key
func (k keyLoader) LoadActorFromKeyIRI(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	// NOTE(marius): should we handle this in the calling code?
	// This feels a little bit to be the wrong place.
	if k.iriIsIgnored(iri) {
		return AnonymousActor, nil, errors.Forbiddenf("actor is blocked")
	}

	if k.st != nil {
		// NOTE(marius): first try to load from local storage
		act, key, err := k.loadLocalKey(iri)
		if err == nil && key != nil {
			k.l.WithContext(lw.Ctx{"key": mask.S(key.PublicKeyPem), "iri": act.ID}).Debugf("found local key and actor")
			return act, key, nil
		}
	}
	return k.loadRemoteKey(iri)
}

func (k keyLoader) loadRemoteKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.c == nil {
		return AnonymousActor, nil, errInvalidClient
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), DefaultKeyWaitLoadTime)
	defer cancelFn()

	// NOTE(marius): then we try to load the IRI as a public key
	return LoadRemoteKey(ctx, k.c, iri)
}

// iriIsIgnored this checks if the incoming iri belongs to any of the hosts/instances/iris in the
// ignored list.
func (k keyLoader) iriIsIgnored(iri vocab.IRI) bool {
	for _, i := range k.ignore {
		if iri.Contains(i, false) {
			return true
		}
	}
	return false
}

func (k keyLoader) loadLocalKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.st == nil {
		return AnonymousActor, nil, errInvalidStorage
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

	var key *vocab.PublicKey

	// NOTE(marius): in the case of the locally saved actors, we don't have *YET* public keys stored
	// as independent objects.
	// Therefore, there's no need to check if the IRI belongs to a Key object, and if that's the case
	// then dereference the owner, as we do in the remote case.
	it, err := k.st.Load(iri)
	if err != nil {
		return act, nil, err
	}

	err = vocab.OnActor(it, func(a *vocab.Actor) error {
		act = *a
		key = &a.PublicKey
		return nil
	})

	return act, key, nil
}

func compatibleVerifyAlgorithms(pubKey crypto.PublicKey) []draft.Algorithm {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return []draft.Algorithm{draft.RSA_SHA256, draft.RSA_SHA512}
	case *ecdsa.PublicKey:
		return []draft.Algorithm{draft.ECDSA_SHA512, draft.ECDSA_SHA256}
	case ed25519.PublicKey:
		return []draft.Algorithm{draft.ED25519}
	}
	return nil
}

// LoadRemoteKey fetches a remote Public Key and returns it's owner.
func LoadRemoteKey(ctx context.Context, c apClient, iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	cl := client.HTTPClient(c)
	if cl == nil {
		return AnonymousActor, nil, errInvalidClient
	}
	resp, err := cl.Get(iri.String())
	if err != nil {
		return AnonymousActor, nil, errors.Annotatef(err, "unable to fetch key")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return AnonymousActor, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusGone, http.StatusNotModified:
		// OK
	default:
		return AnonymousActor, nil, errors.NewFromStatus(resp.StatusCode, "unable to fetch key")
	}

	key := new(vocab.PublicKey)
	act := vocab.Actor{}

	// NOTE(marius): try to decode the response body as a PublicKey
	if err = jsonld.Unmarshal(body, key); err != nil || key.Owner == vocab.EmptyIRI {
		// NOTE(marius): then we try to decode the body as an Actor
		err = jsonld.Unmarshal(body, &act)
	}
	// NOTE(marius): if we were unable to decode a PublicKey, nor an Actor that matches the IRI, we have failed.
	if !(key.ID.Equal(iri) || act.ID.Equal(iri)) {
		if err != nil {
			err = errors.Annotatef(err, "unable to decode key or actor")
		} else {
			err = errors.Newf("unable to decode key or actor")
		}
		return AnonymousActor, nil, err
	}

	if act.ID.Equal(iri) {
		key = &act.PublicKey
	}
	// NOTE(marius): we successfully loaded a PublicKey, we try to load the Actor from its Owner property
	if key.ID.Equal(iri) {
		// NOTE(marius): the SWICG document linked at the LoadActorFromIRIKey method mentions
		// that we can use both key.Owner or key.Controller, however we don't have Controller
		// in the PublicKey struct. We should probably change that.
		it, err := c.CtxLoadIRI(ctx, key.Owner)
		if err != nil {
			return AnonymousActor, key, errors.NewFromStatus(resp.StatusCode, "unable to fetch actor")
		}

		_ = vocab.OnActor(it, func(actor *vocab.Actor) error {
			act = *actor
			return nil
		})
	}

	return act, key, nil
}
