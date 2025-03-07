package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-fed/httpsig"
	"github.com/openshift/osin"
)

var AnonymousActor = vocab.Actor{
	ID:   vocab.PublicNS,
	Type: vocab.ActorType,
	Name: vocab.NaturalLanguageValues{
		vocab.LangRefValue{
			Ref:   vocab.NilLangRef,
			Value: vocab.Content("Anonymous"),
		},
	},
}

// readStore
type readStore interface {
	// Load returns an Item or an ItemCollection from an IRI
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
}

type keyLoader struct {
	loadActorFromKeyFn func(vocab.IRI) (*vocab.Actor, *vocab.PublicKey, error)
	logFn              LoggerFn
	acc                *vocab.Actor
}

func (k *keyLoader) GetKey(id string) (crypto.PublicKey, error) {
	iri := vocab.IRI(id)
	_, err := iri.URL()
	if err != nil {
		return nil, err
	}

	var act *vocab.Actor
	var key *vocab.PublicKey

	k.logFn(nil, "Loading Actor from Key IRI: %s", iri)
	if act, key, err = k.loadActorFromKeyFn(iri); err != nil && !errors.IsNotModified(err) {
		if errors.IsForbidden(err) {
			return nil, err
		}
		return nil, errors.NewNotFound(err, "unable to find actor matching key id %s", iri)
	}
	if vocab.IsNil(act) {
		return nil, errors.NotFoundf("unable to find actor matching key id %s", iri)
	}
	if !vocab.IsObject(act) {
		return nil, errors.NotFoundf("unable to load actor matching key id %s, received %T", iri, act)
	}
	k.acc = act

	if key == nil {
		return nil, errors.NotFoundf("invalid key loaded %s for actor %s", iri, act.ID)
	}

	block, _ := pem.Decode([]byte(key.PublicKeyPem))
	if block == nil {
		return nil, errors.Newf("failed to parse PEM block containing the public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

type oauthStore interface {
	readStore
	LoadAccess(token string) (*osin.AccessData, error)
}

type oauthLoader struct {
	logFn LoggerFn
	acc   *vocab.Actor
	s     oauthStore
}

func firstOrItem(it vocab.Item) (vocab.Item, error) {
	if it.IsCollection() {
		err := vocab.OnCollectionIntf(it, func(col vocab.CollectionInterface) error {
			it = col.Collection().First()
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return it, nil
}

func unauthorized(err error) error {
	return errors.NewUnauthorized(err, "Unable to validate actor from Bearer token")
}

func assertToBytes(in interface{}) ([]byte, error) {
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

func (k *oauthLoader) Verify(r *http.Request) (error, string) {
	bearer := osin.CheckBearerAuth(r)
	if bearer == nil {
		return errors.BadRequestf("could not load bearer token from request"), ""
	}
	dat, err := k.s.LoadAccess(bearer.Code)
	if err != nil {
		return err, ""
	}
	if dat == nil || dat.UserData == nil {
		return errors.NotFoundf("unable to load bearer"), ""
	}
	if iri, err := assertToBytes(dat.UserData); err == nil {
		it, err := k.s.Load(vocab.IRI(iri))
		if err != nil {
			return unauthorized(err), ""
		}
		if vocab.IsNil(it) {
			return unauthorized(err), ""
		}
		if it, err = firstOrItem(it); err != nil {
			return unauthorized(err), ""
		}
		err = vocab.OnActor(it, func(act *vocab.Actor) error {
			k.acc = act
			return nil
		})
		if err != nil {
			return unauthorized(err), ""
		}
	} else {
		return errors.Unauthorizedf("unable to load from bearer"), ""
	}
	return nil, ""
}

func verifyHTTPSignature(r *http.Request, keyGetter *keyLoader) error {
	v, err := httpsig.NewVerifier(r)
	if err != nil {
		return errors.Annotatef(err, "unable to initialize HTTP Signatures verifier")
	}
	k, err := keyGetter.GetKey(v.KeyId())
	if err != nil {
		return errors.Annotatef(err, "unable to load public key based on signature")
	}
	algos := compatibleVerifyAlgorithms(k)
	for _, algo := range algos {
		if err = v.Verify(k, algo); err == nil {
			return nil
		}
	}
	return errors.Newf("unable to verify HTTP Signature with any of the attempted algorithms: %v", algos)
}

func compatibleVerifyAlgorithms(pubKey crypto.PublicKey) []httpsig.Algorithm {
	algos := make([]httpsig.Algorithm, 0)
	switch pubKey.(type) {
	case *rsa.PublicKey:
		algos = append(algos, httpsig.RSA_SHA256, httpsig.RSA_SHA512)
	case *ecdsa.PublicKey:
		algos = append(algos, httpsig.ECDSA_SHA512, httpsig.ECDSA_SHA256)
	case ed25519.PublicKey:
		algos = append(algos, httpsig.ED25519)
	}
	return algos
}

func getAuthorization(hdr string) (string, string) {
	pieces := strings.SplitN(hdr, " ", 2)
	if len(pieces) < 2 {
		return hdr, ""
	}
	return pieces[0], pieces[1]
}

// LoadActorFromRequest reads the Authorization header of an HTTP request and tries to decode it either
// an OAuth2 or HTTP Signatures:
//
// * For OAuth2 it tries to load the matching local actor and use it further in the processing logic.
// * For HTTP Signatures it tries to load the federated actor and use it further in the processing logic.
func (s *Server) LoadActorFromRequest(r *http.Request, toIgnore ...vocab.IRI) (vocab.Actor, error) {
	// NOTE(marius): if the storage is nil, we can still use the remote client in the load function
	var st oauthStore
	if s.Server != nil && s.Server.Storage != nil {
		st, _ = s.Server.Storage.(oauthStore)
	}
	isLocalFn := func(iri vocab.IRI) bool {
		for _, i := range s.localURLs {
			if iri.Contains(i, true) {
				return true
			}
		}
		return false
	}
	var logFn LoggerFn = func(ctx lw.Ctx, msg string, p ...interface{}) {
		s.l.WithContext(ctx).Debugf(msg, p...)
	}
	ar := ClientResolver(s.cl,
		SolverWithLogger(logFn), SolverWithStorage(st), SolverWithLocalIRIFn(isLocalFn),
		SolverWithIgnoreList(toIgnore...),
	)
	return ar.LoadActorFromRequest(r)
}
