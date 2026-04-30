package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"io"
	"net/http"

	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
)

// LoadRemoteKey fetches a remote Public Key and returns it's owner.
func LoadRemoteKey(_ context.Context, c ActivityPubClient, iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	return (&localRemoteLoader{c: c}).loadRemoteKey(iri)
}

type keyLoader interface {
	loadKey(string) (vocab.Actor, *vocab.PublicKey, error)
}

type localRemoteLoader struct {
	actor vocab.Actor
	c     ActivityPubClient
	st    readStore
}

var errEmptyIRI = errors.Newf("empty IRI")

func (k localRemoteLoader) loadRemoteKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.c == nil {
		return AnonymousActor, nil, errInvalidClient
	}
	if iri == "" {
		return AnonymousActor, nil, errEmptyIRI
	}

	req, err := http.NewRequest(http.MethodGet, string(iri), nil)
	if err != nil {
		return AnonymousActor, nil, errors.Annotatef(err, "unable to create request")
	}

	resp, err := k.c.Do(req)
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
			err = errors.Annotatef(err, "unable to decode key or actor: %s", iri)
		} else {
			err = errors.Newf("unable to decode key or actor: %s", iri)
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
		it, err := k.c.LoadIRI(key.Owner)
		if err != nil {
			return AnonymousActor, key, errors.NewFromStatus(resp.StatusCode, "unable to fetch actor: %s", iri)
		}

		_ = vocab.OnActor(it, func(actor *vocab.Actor) error {
			act = *actor
			return nil
		})
	}

	return act, key, nil
}

func (k localRemoteLoader) loadLocalKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
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

func (k localRemoteLoader) loadKey(keyID string) (vocab.Actor, *vocab.PublicKey, error) {
	// NOTE(marius): we first try to verify with the copy of the key stored locally if it exists.
	actor, key, _ := k.loadLocalKey(vocab.IRI(keyID))
	if key != nil {
		return actor, key, nil
	}

	// NOTE(marius): if local verification fails, we try to fetch a fresh copy of the key and try again.
	return k.loadRemoteKey(vocab.IRI(keyID))
}

func (k *localRemoteLoader) ResolveKey(_ context.Context, id string) (httpsig.Key, error) {
	key := httpsig.Key{KeyID: id}
	act, pub, err := k.loadKey(id)
	if err != nil {
		return key, err
	}
	k.actor = act
	key.Algorithm, key.Key, err = rfcAlgorithmFromPublicKey(pub)
	return key, err
}

func rfcAlgorithmFromPublicKey(pub *vocab.PublicKey) (httpsig.SignatureAlgorithm, crypto.PublicKey, error) {
	pkey, err := toCryptoPublicKey(*pub)
	if err != nil {
		return "", nil, err
	}

	var key crypto.PublicKey
	var alg httpsig.SignatureAlgorithm
	switch pk := pkey.(type) {
	case *rsa.PublicKey:
		switch pk.Size() {
		case 128, 256:
			alg = httpsig.RsaPkcs1v15Sha256
		case 384:
			alg = httpsig.RsaPkcs1v15Sha384
		case 512:
			alg = httpsig.RsaPkcs1v15Sha512
		}
		key = pk
	case *ecdsa.PublicKey:
		if p := pk.Params(); p != nil {
			switch p.BitSize {
			case 128, 256:
				alg = httpsig.EcdsaP256Sha256
			case 384:
				alg = httpsig.EcdsaP384Sha384
			case 512:
				alg = httpsig.EcdsaP521Sha512
			}
		}
		key = pk
	case ed25519.PublicKey:
		alg = httpsig.Ed25519
		key = pk
	}
	return alg, key, nil
}

func (k *localRemoteLoader) Actor() vocab.Actor {
	return k.actor
}
