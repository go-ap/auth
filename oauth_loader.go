package auth

import (
	"net/http"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

type oauthLoader config

// OAuth2Resolver
func OAuth2Resolver(cl Client, initFns ...SolverInitFn) ActorVerifier {
	c := config{c: cl}
	for _, fn := range initFns {
		fn(&c)
	}
	ol := oauthLoader(c)
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
