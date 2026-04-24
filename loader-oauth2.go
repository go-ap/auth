package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

type oauthLoader struct {
	st oauthStore
	l  lw.Logger
}

// OAuth2
func OAuth2(initFns ...InitFn) oauthLoader {
	c := Config(initFns...)
	return oauthLoader{
		st: c.st,
		l:  c.l,
	}
}

var (
	errInvalidStorage = errors.Newf("invalid storage")
	errInvalidClient  = errors.Newf("invalid client")
)

func (k oauthLoader) VerifyAccessCode(tok string) (vocab.Actor, error) {
	act := AnonymousActor
	if k.st == nil {
		return act, errInvalidStorage
	}
	dat, err := k.st.LoadAccess(tok)
	if err != nil {
		return act, errors.NewUnauthorized(err, "Unauthorized").Challenge("oauth2")
	}
	if dat == nil || dat.UserData == nil {
		return act, errors.NotFoundf("unable to load access data")
	}
	if iri, err := assertToBytes(dat.UserData); err == nil {
		it, err := k.st.Load(vocab.IRI(iri))
		if err != nil {
			return act, errors.NewUnauthorized(err, "Unauthorized").Challenge("oauth2")
		}
		if vocab.IsNil(it) {
			return act, errors.NewUnauthorized(err, "Unauthorized").Challenge("oauth2")
		}
		if it, err = firstOrItem(it); err != nil {
			return act, errors.NewUnauthorized(err, "Unauthorized").Challenge("oauth2")
		}
		err = vocab.OnActor(it, func(actor *vocab.Actor) error {
			act = *actor
			return nil
		})
		if err != nil {
			return act, errors.NewUnauthorized(err, "Unauthorized").Challenge("oauth2")
		}
	} else {
		return act, errors.Unauthorizedf("unable to load from bearer")
	}
	return act, nil
}

func (k oauthLoader) Verify(r *http.Request) (vocab.Actor, error) {
	if r == nil || r.Header == nil {
		return AnonymousActor, nil
	}
	if k.st == nil {
		return AnonymousActor, errInvalidStorage
	}
	act := AnonymousActor
	bearer := osin.CheckBearerAuth(r)
	if bearer == nil {
		return act, errors.BadRequestf("could not load bearer token from request")
	}
	return k.VerifyAccessCode(bearer.Code)
}

var AnonymousActor = vocab.Actor{
	ID: vocab.PublicNS,
	// NOTE(marius): this is not a standard ActivityPub type, so it might confuse applications
	Type: vocab.ActorType,
	Name: vocab.DefaultNaturalLanguage("Anonymous"),
}

func firstOrItem(it vocab.Item) (vocab.Item, error) {
	if vocab.IsNil(it) {
		return it, nil
	}
	if it.IsCollection() {
		_ = vocab.OnCollectionIntf(it, func(col vocab.CollectionInterface) error {
			it = col.Collection().First()
			return nil
		})
	}
	return it, nil
}

func assertToBytes(in any) ([]byte, error) {
	var ok bool
	var data string
	if in == nil {
		return nil, nil
	} else if data, ok = in.(string); ok {
		return []byte(data), nil
	} else if byt, ok := in.([]byte); ok {
		return byt, nil
	} else if byt, ok := in.(json.RawMessage); ok {
		return byt, nil
	} else if str, ok := in.(fmt.Stringer); ok {
		return []byte(str.String()), nil
	}
	return nil, errors.Errorf(`Could not assert "%v" to string`, in)
}

func getAuthorization(hdr string) (string, string) {
	pieces := strings.SplitN(hdr, " ", 2)
	if len(pieces) < 2 {
		return hdr, ""
	}
	return pieces[0], pieces[1]
}
