package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

type syncedNonceStore struct {
	sync.Map
}

func (s *syncedNonceStore) Seen(n string) bool {
	_, ok := s.Map.LoadOrStore(n, struct{}{})
	return ok
}

var errInvalidNonce = errors.Newf("nonce already seen")

func (s *syncedNonceStore) CheckNonce(_ context.Context, n string) error {
	_, ok := s.Map.LoadOrStore(n, struct{}{})
	if ok {
		return errInvalidNonce
	}
	return nil
}

var nonceStore = new(syncedNonceStore)

var (
	sigValidDeltaDuration = time.Minute
	sigMaxAgeDuration     = 30 * time.Second //10 * 365 * 24 * time.Hour
)

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
		return AnonymousActor, err
	}
	return resolver.Actor(), nil
}
