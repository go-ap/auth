package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"git.sr.ht/~mariusor/lw"
	"github.com/dadrus/httpsig"
	"github.com/dunglas/httpsfv"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

type syncedNonceStore struct {
	sync.Map
}

var errInvalidNonce = func(n string) error { return fmt.Errorf("nonce already seen: %s", n) }

func (s *syncedNonceStore) CheckNonce(_ context.Context, n httpsig.NonceValue) error {
	if !n.Present {
		return nil
	}
	if _, exists := s.LoadOrStore(n.Value, struct{}{}); exists {
		return errInvalidNonce(n.Value)
	}
	return nil
}

type actorKeyLoader interface {
	httpsig.KeyResolver
	Actor() vocab.Actor
}

func signatureInputAlgorithm(header http.Header) (alg httpsig.SignatureAlgorithm) {
	values := header.Values("Signature-Input")
	inputDict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return
	}

	for _, label := range inputDict.Names() {
		m, _ := inputDict.Get(label)

		sigParams, ok := m.(httpsfv.InnerList)
		if !ok {
			return alg
		}
		param, ok := sigParams.Params.Get("alg")
		if !ok {
			return alg
		}
		value, ok := param.(string)
		if !ok {
			return alg
		}

		alg = httpsig.SignatureAlgorithm(value)
	}

	return alg
}

type hardcodedAlgResolver struct {
	actorKeyLoader
	alg httpsig.SignatureAlgorithm
}

func (k hardcodedAlgResolver) ResolveKey(ctx context.Context, keyID string) (httpsig.Key, error) {
	key, err := k.actorKeyLoader.ResolveKey(ctx, keyID)
	if key.Algorithm == "" {
		key.Algorithm = k.alg
	}
	return key, err
}

// VerifyRFCSignature checks for RFC9421 compatible HTTP signatures.
// It is based on the common-fate/httpsig/verifier.Parse functionality adapted for go-ap.
func (k httpSigVerifier) VerifyRFCSignature(req *http.Request) (vocab.Actor, error) {
	if req == nil {
		return AnonymousActor, errInvalidRequest
	}
	resolver, ok := k.loader.(actorKeyLoader)
	if !ok {
		return AnonymousActor, errInvalidClient
	}
	if k.ncFn == nil {
		k.ncFn = new(syncedNonceStore)
	}
	if alg := signatureInputAlgorithm(req.Header); alg != "" {
		resolver = hardcodedAlgResolver{alg: alg, actorKeyLoader: resolver}
	}
	// Create a verifier
	verifier, err := httpsig.NewVerifier(
		resolver,
		httpsig.WithNonceChecker(k.ncFn),
		httpsig.WithValidityTolerance(sigValidDeltaDuration),
		httpsig.WithMaxAge(sigMaxAgeDuration),
		httpsig.WithCreatedTimestampRequired(false),
		httpsig.WithExpiredTimestampRequired(false),
		httpsig.WithValidateAllSignatures(),
	)
	if err != nil {
		return AnonymousActor, err
	}

	msg := httpsig.MessageFromRequest(req)
	if forwardedHost := req.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		msg.Authority = forwardedHost
	}
	if err = verifier.Verify(msg); err != nil {
		k.l.WithContext(lw.Ctx{"headers": msg.Header, "authority": msg.Authority, "url": msg.URL.String(), "err": err}).Warnf("unable to verify actor")
		if act := resolver.Actor(); !vocab.IsNil(act) && act.ID != "" {
			err = errors.Annotatef(err, "actor IRI %s", act.ID)
		}
		return AnonymousActor, err
	}
	return resolver.Actor(), nil
}
