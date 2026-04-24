package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	draft "github.com/go-fed/httpsig"
)

type httpSigVerifier struct {
	loader keyLoader
	l      lw.Logger
}

// HTTPSignature returns a HTTP-Signature validator for loading f
func HTTPSignature(initFns ...InitFn) httpSigVerifier {
	c := Config(initFns...)
	v := httpSigVerifier{
		loader: keyLoader{c: c.c, st: c.st},
		l:      c.l,
	}
	return v
}

func (k httpSigVerifier) VerifyDraftSignature(r *http.Request) (vocab.Actor, error) {
	v, err := draft.NewVerifier(r)
	if err != nil {
		return AnonymousActor, errors.NewBadRequest(err, "unable to initialize HTTP Signatures verifier")
	}

	draftVerifyFn := func(pubKey *vocab.PublicKey) error {
		pk, err := toCryptoPublicKey(*pubKey)
		if err != nil {
			return errors.Annotatef(err, "invalid public key")
		}

		algs := compatibleDraftVerifyAlgorithms(pk)
		errs := make([]error, 0, len(algs))
		for _, algo := range algs {
			if err = v.Verify(pk, algo); err == nil {
				return nil
			}
			errs = append(errs, errors.Annotatef(err, "failed %s", algo))
		}
		return errors.Join(errs...)
	}

	actor, key, err := k.loader.loadKey(v.KeyId())
	if err != nil {
		return AnonymousActor, errors.Annotatef(err, "unable to load public key based on signature")
	}

	if err = draftVerifyFn(key); err != nil {
		return AnonymousActor, err
	}
	return actor, nil
}

func (k httpSigVerifier) Verify(r *http.Request) (vocab.Actor, error) {
	if k.loader.st == nil {
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

func compatibleDraftVerifyAlgorithms(pubKey crypto.PublicKey) []draft.Algorithm {
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
