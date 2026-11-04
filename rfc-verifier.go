package auth

import (
	"context"
	"net/http"

	"github.com/dadrus/httpsig"
	"github.com/dunglas/httpsfv"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

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

func (k hardcodedAlgResolver) ResolveKey(ctx context.Context, sigInfo httpsig.SignatureInfo) (httpsig.KeyInfo, error) {
	key, err := k.actorKeyLoader.ResolveKey(ctx, sigInfo)
	return key, err
}

func HTTPSigMsgFromRequest(req *http.Request) *httpsig.Message {
	msg := httpsig.MessageFromRequest(req)
	// NOTE(marius): on incoming requests the req.URL.Host is empty,
	//  but to match the signature base it needs to be completed with the authority
	if msg.URL.Host == "" {
		msg.URL.Host = msg.Authority
	}
	if msg.URL.Path == "" {
		msg.URL.Path = "/"
	}
	// NOTE(marius): similarly if the protocol is empty we either hardcoded to https,
	//  or we load it from the X-Forwarded-Proto if we're behind proxy.
	if msg.URL.Scheme == "" {
		msg.URL.Scheme = "https"
		if proto := msg.Header.Get("X-Forwarded-Proto"); proto != "" {
			msg.URL.Scheme = proto
		}
	}
	// NOTE(marius): for some fetch requests, we have a non empty fragment
	//  I'm not clear if this case is handled correctly on the verifier side.
	if msg.URL.Fragment != "" {
		req.URL.Fragment = ""
	}
	return msg
}

// VerifyRFCSignature checks for RFC9421 compatible HTTP signatures.
// It is based on the github.com/dadrus/httpsig.Verifier() functionality adapted for go-ap.
func (k httpSigVerifier) VerifyRFCSignature(req *http.Request) (vocab.Actor, error) {
	if req == nil {
		return AnonymousActor, errInvalidRequest
	}
	resolver, ok := k.loader.(actorKeyLoader)
	if !ok {
		return AnonymousActor, errInvalidClient
	}
	if alg := signatureInputAlgorithm(req.Header); alg != "" {
		resolver = hardcodedAlgResolver{alg: alg, actorKeyLoader: resolver}
	}
	// Create a verifier
	verifier, err := httpsig.NewVerifier(
		resolver,
		httpsig.WithValidityTolerance(sigValidDeltaDuration),
		httpsig.WithMaxAge(sigMaxAgeDuration),
		httpsig.WithCreatedTimestamp(false),
		httpsig.WithExpiresTimestamp(false),
		httpsig.WithValidateAllSignatures(),
	)
	if err != nil {
		return AnonymousActor, err
	}

	msg := HTTPSigMsgFromRequest(req)
	if _, err = verifier.Verify(msg); err != nil {
		if act := resolver.Actor(); !vocab.IsNil(act) && act.ID != "" {
			err = errors.Annotatef(err, "actor IRI %s", act.ID)
		}
		return AnonymousActor, err
	}
	return resolver.Actor(), nil
}
