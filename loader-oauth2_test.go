package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-ap/jsonld"
	"github.com/google/go-cmp/cmp"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/openshift/osin"
)

func TestOAuth2_VerifyAccessCode(t *testing.T) {
	type fields struct {
		localURLs vocab.IRIs
		cl        Client
		st        oauthStore
	}
	tests := []struct {
		name    string
		fields  fields
		code    string
		want    vocab.Actor
		wantErr error
	}{
		{
			name:    "empty",
			fields:  fields{},
			code:    "",
			want:    AnonymousActor,
			wantErr: errInvalidStorage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := oauthLoader(config{
				st: tt.fields.st,
				iriIsLocal: func(iri vocab.IRI) bool {
					return slices.Contains(tt.fields.localURLs, iri)
				},
				c: tt.fields.cl,
				l: lw.Dev(lw.SetOutput(t.Output())),
			})

			got, err := s.VerifyAccessCode(tt.code)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("VerifyAccessCode() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want) {
				t.Errorf("VerifyAccessCode() got = %s", cmp.Diff(tt.want, got))
			}
		})
	}
}

var ll = lw.Dev()
var cl = client.New(
	client.WithLogger(ll.WithContext(lw.Ctx{"log": "client"})),
	client.SkipTLSValidation(true),
)

func isNotLocal(_ vocab.IRI) bool {
	return false
}

var prv, _ = rsa.GenerateKey(rand.Reader, 1024)

func pemEncodePublicKey(prvKey *rsa.PrivateKey) string {
	pubKey := prvKey.PublicKey
	pubEnc, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		panic(err)
	}
	p := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubEnc,
	}

	return string(pem.EncodeToMemory(&p))
}

func mockActor(base string) vocab.Actor {
	return vocab.Actor{
		ID:   vocab.IRI(base + "/jdoe"),
		Type: vocab.PersonType,
		PublicKey: vocab.PublicKey{
			ID:           vocab.IRI(base + "/jdoe#main"),
			Owner:        vocab.IRI(base + "/jdoe"),
			PublicKeyPem: pemEncodePublicKey(prv),
		},
	}
}

func mockKeyAndActorHandler(base string) http.Handler {
	cnt := 0
	actor := mockActor(base)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		status := http.StatusNotModified
		if cnt == 0 {
			payload, _ = jsonld.Marshal(actor)
			if filepath.Base(r.URL.Path) == "key" {
				actor.PublicKey.ID = vocab.IRI(base + "/jdoe/key")
				payload, _ = jsonld.Marshal(actor.PublicKey)
			}
			status = http.StatusOK
			w.Header().Set("Cache-Control", "public")
		}
		cnt++

		w.WriteHeader(status)
		_, _ = w.Write(payload)
	})
}

var srv, _ = testServerWithURL(mockKeyAndActorHandler)

func testServerWithURL(handler func(string) http.Handler) (*httptest.Server, error) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ts := httptest.NewUnstartedServer(nil)
	ts.Listener = l
	ts.Config.Handler = handler(fmt.Sprintf("http://%s", ts.Listener.Addr().String()))

	ts.Start()
	return ts, nil
}

type mockStorage struct {
	it   vocab.Item
	data *osin.AccessData
}

func (m mockStorage) Load(iri vocab.IRI, check ...filters.Check) (vocab.Item, error) {
	return m.it, nil
}

func (m mockStorage) LoadAccess(token string) (*osin.AccessData, error) {
	return m.data, nil
}

func mockStore(it vocab.Item, access *osin.AccessData) mockStorage {
	return mockStorage{
		it:   it,
		data: access,
	}
}

var _ oauthStore = mockStorage{}

func areErrors(a, b any) bool {
	_, ok1 := a.(error)
	_, ok2 := b.(error)
	return ok1 && ok2
}

func compareErrors(x, y any) bool {
	xe := x.(error)
	ye := y.(error)
	if errors.Is(xe, ye) || errors.Is(ye, xe) {
		return true
	}
	return xe.Error() == ye.Error()
}

var EquateWeakErrors = cmp.FilterValues(areErrors, cmp.Comparer(compareErrors))
