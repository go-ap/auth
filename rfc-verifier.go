package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/dadrus/httpsig"
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

var nonceStore = new(syncedNonceStore)

type actorKeyLoader interface {
	httpsig.KeyResolver
	Actor() vocab.Actor
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
	// Create a verifier
	verifier, err := httpsig.NewVerifier(
		resolver,
		httpsig.WithNonceChecker(nonceStore),
		httpsig.WithValidityTolerance(sigValidDeltaDuration),
		httpsig.WithMaxAge(sigMaxAgeDuration),
		httpsig.WithCreatedTimestampRequired(false),
		httpsig.WithExpiredTimestampRequired(false),
		httpsig.WithValidateAllSignatures(),
	)
	if err != nil {
		return AnonymousActor, err
	}

	if err = verifier.Verify(httpsig.MessageFromRequest(req)); err != nil {
		if act := resolver.Actor(); !vocab.IsNil(act) && act.ID != "" {
			err = errors.Annotatef(err, "actor IRI %s", act.ID)
		}
		return AnonymousActor, err
	}
	return resolver.Actor(), nil
}
