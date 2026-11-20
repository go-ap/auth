package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"net/http"
	"strings"

	"github.com/carlmjohnson/requests"
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
	st    ReadStore
}

var errEmptyIRI = errors.Newf("empty IRI")

func (k localRemoteLoader) loadRemoteKey(keyID vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.c == nil {
		return AnonymousActor, nil, errInvalidClient
	}
	if keyID == "" {
		return AnonymousActor, nil, errEmptyIRI
	}

	req, err := requests.URL(string(keyID)).Method(http.MethodGet).Request(context.Background())
	if err != nil {
		return AnonymousActor, nil, errors.Annotatef(err, "unable to create request: %s", keyID)
	}

	resp, err := k.c.Do(req)
	if err != nil {
		return AnonymousActor, nil, errors.Annotatef(err, "unable to fetch key: %s", keyID)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return AnonymousActor, nil, err
	}

	switch resp.StatusCode {
	case http.StatusGone:
		return AnonymousActor, nil, errors.Gonef("key does not exist: %s", keyID)
	case http.StatusOK, http.StatusNotModified:
		// OK
	default:
		if errb, _ := errors.UnmarshalJSON(body); len(errb) > 0 {
			err = errors.AnnotateFromStatus(errors.Join(errb...), resp.StatusCode, "unable to fetch key: %s", keyID)
		} else {
			if len(body) > 0 {
				err = errors.AnnotateFromStatus(errors.Newf("%s", body[:min(512, len(body))]), resp.StatusCode, "unable to fetch key: %s", keyID)
			} else {
				err = errors.NewFromStatus(resp.StatusCode, "unable to fetch key: %s", keyID)
			}
		}
		return AnonymousActor, nil, err
	}

	key := new(vocab.PublicKey)
	act := new(vocab.Actor)

	// NOTE(marius): try to decode the response body as a PublicKey
	if err = jsonld.Unmarshal(body, key); err != nil || key.Owner == vocab.EmptyIRI {
		// NOTE(marius): then we try to decode the body as an Actor
		err = jsonld.Unmarshal(body, act)
	}
	if err != nil {
		return AnonymousActor, nil, errors.Annotatef(err, "unable to decode key or actor: %s", keyID)
	}

	// NOTE(marius): if we were unable to decode a PublicKey, nor an Actor that matches the IRI, we have failed.
	if !key.ID.Equal(keyID) && !act.ID.Equal(keyID) {
		return AnonymousActor, nil, errors.Newf("unable to decode key or actor: %s", keyID)
	}

	// NOTE(marius): the received IRI was an actor's, we return its embedded Public Key
	if act.ID.Equal(keyID) {
		key = &act.PublicKey
	}

	// NOTE(marius): the received IRI was a PublicKey, we try to load the Actor from its Owner property
	// We check the
	if key.ID.Equal(keyID) && !act.ID.Equal(key.Owner) {
		// NOTE(marius): the SWICG document linked at the LoadActorFromIRIKey method mentions
		// that we can use both key.Owner or key.Controller, however we don't have Controller
		// in the PublicKey struct. We should probably change that.
		it, err := k.c.CtxLoadIRI(context.Background(), key.Owner)
		if err != nil {
			return AnonymousActor, nil, errors.NewFromStatus(resp.StatusCode, "unable to fetch key owner actor %s for key: %s", key.Owner, keyID)
		}

		act, err = vocab.ToActor(it)
		if err != nil {
			return AnonymousActor, nil, errors.Annotatef(err, "key owner %s does not resolve to a valid actor for key: %s", key.Owner, keyID)
		}

		// NOTE(marius): for the cases where the incoming KeyID leads to a Key with an Owner actor which has
		// a different keyID in its PublicKey value, we consider it might be an exploit attempt, and double-check
		// the key material to match.
		if !act.PublicKey.ID.Equal(keyID) && !pemValuesAreEqual(act.PublicKey.PublicKeyPem, key.PublicKeyPem) {
			return AnonymousActor, nil, errors.Errorf("owner's public key id %s does not match the received key: %s", act.PublicKey.ID, keyID)
		}
		key = &act.PublicKey
	}

	return *act, key, nil
}

func pemValuesAreEqual(pem1, pem2 string) bool {
	pubBytes1, _ := pem.Decode([]byte(pem1))
	pubBytes2, _ := pem.Decode([]byte(pem2))
	if pubBytes1 == nil || pubBytes2 == nil {
		return false
	}
	return pubBytes1.Type == pubBytes2.Type && bytes.Equal(pubBytes1.Bytes, pubBytes2.Bytes)
}

func (k localRemoteLoader) loadLocalKey(iri vocab.IRI) (vocab.Actor, *vocab.PublicKey, error) {
	if k.st == nil {
		return AnonymousActor, nil, errInvalidStorage
	}

	act := AnonymousActor
	u, err := iri.URL()
	if err != nil {
		return act, nil, errors.Annotatef(err, "invalid URL to load: %s", iri)
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

	return act, key, err
}

func validatePublicKey(pub vocab.PublicKey) error {
	if len(pub.PublicKeyPem) == 0 {
		return errors.Newf("invalid public key with empty PEM value")
	}
	if !strings.HasPrefix(pub.PublicKeyPem, "-----") {
		debug := pub.PublicKeyPem[:min(len(pub.PublicKeyPem), max(20, strings.Index(pub.PublicKeyPem, "\n")))]
		return errors.Newf("invalid public key header %s", debug)
	}
	return nil
}

func (k localRemoteLoader) loadKey(keyID string) (vocab.Actor, *vocab.PublicKey, error) {
	// NOTE(marius): we first try to verify with the copy of the key stored locally if it exists.
	actor, key, err := k.loadLocalKey(vocab.IRI(keyID))
	if err == nil && key != nil && validatePublicKey(actor.PublicKey) == nil {
		return actor, key, nil
	}
	// NOTE(marius): if local verification fails, we try to fetch a fresh copy of the key and try again.
	actor, key, err = k.loadRemoteKey(vocab.IRI(keyID))
	if err != nil {
		return AnonymousActor, nil, err
	}
	if err = validatePublicKey(actor.PublicKey); err != nil {
		return AnonymousActor, nil, err
	}
	return actor, key, nil
}

func (k *localRemoteLoader) ResolveKey(_ context.Context, sigInfo httpsig.SignatureInfo) (httpsig.KeyInfo, error) {
	key := httpsig.Key{}
	keyID, ok := sigInfo.Parameters.KeyID()
	if !ok {
		return httpsig.KeyInfo{}, errors.Newf("invalid keyID in the signature parameters")
	}
	act, pub, err := k.loadKey(keyID)
	if err != nil {
		return httpsig.KeyInfo{}, err
	}
	pkey, err := pub.CryptoValue()
	if err != nil {
		return httpsig.KeyInfo{}, err
	}
	k.actor = act
	alg, ok := sigInfo.Parameters.Alg()
	if !ok {
		alg = rfcAlgorithmFromPublicKey(pkey)
	}
	key.Algorithm = alg
	key.Material = pkey
	return httpsig.KeyInfo{Key: key}, nil
}

func rfcAlgorithmFromPublicKey(pkey crypto.PublicKey) httpsig.SignatureAlgorithm {
	switch pk := pkey.(type) {
	case *rsa.PublicKey:
		switch pk.Size() {
		case 128, 256:
			return httpsig.RsaPkcs1v15Sha256
		case 384:
			return httpsig.RsaPkcs1v15Sha384
		case 512:
			return httpsig.RsaPkcs1v15Sha512
		}
	case *ecdsa.PublicKey:
		if p := pk.Params(); p != nil {
			switch p.BitSize {
			case 128, 256:
				return httpsig.EcdsaP256Sha256
			case 384:
				return httpsig.EcdsaP384Sha384
			case 512:
				return httpsig.EcdsaP521Sha512
			}
		}
	case ed25519.PublicKey:
		return httpsig.Ed25519
	default:
	}
	return "unknown"
}

func (k *localRemoteLoader) Actor() vocab.Actor {
	return k.actor
}
