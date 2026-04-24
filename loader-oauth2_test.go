package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"github.com/google/go-cmp/cmp"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
)

func TestOAuth2_VerifyAccessCode(t *testing.T) {
	type fields struct {
		localURLs vocab.IRIs
		cl        *client.C
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
			s := oauthLoader{
				st: tt.fields.st,
				l:  lw.Dev(lw.SetOutput(t.Output())),
			}

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

func mockActorKey(id, owner vocab.IRI, prv *rsa.PrivateKey) vocab.PublicKey {
	return vocab.PublicKey{
		ID:           id,
		Owner:        owner,
		PublicKeyPem: pemEncodePublicKey(prv),
	}
}

func mockActor(base string) vocab.Actor {
	iri := vocab.IRI(base + "/~jdoe")
	return vocab.Actor{
		ID:        iri,
		Type:      vocab.PersonType,
		PublicKey: mockActorKey(iri+"#main", iri, prv),
	}
}

func mockKeyAndActorHandler(base string) http.Handler {
	actor := mockActor(base)
	res := make(map[string][]byte)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusNotModified
		payload, ok := res[r.URL.Path]

		if !ok {
			status = http.StatusOK
			payload, _ = jsonld.Marshal(actor)
			if filepath.Base(r.URL.Path) == "key" {
				actor.PublicKey.ID = vocab.IRI(base + "/~jdoe/key")
				payload, _ = jsonld.Marshal(actor.PublicKey)
			}
			res[r.URL.Path] = payload
		}

		w.Header().Set("Cache-Control", "public")
		w.WriteHeader(status)
		_, _ = w.Write(payload)
	})
}

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

func TestOAuth2(t *testing.T) {
	mockLogger := lw.Dev(lw.SetOutput(t.Output()))
	tests := []struct {
		name    string
		initFns []InitFn
		want    oauthLoader
	}{
		{
			name: "empty",
			want: oauthLoader{l: lw.Nil()},
		},
		{
			name:    "with logger",
			initFns: []InitFn{WithLogger(mockLogger)},
			want:    oauthLoader{l: mockLogger},
		},
		{
			name:    "with storage",
			initFns: []InitFn{WithStorage(st())},
			want:    oauthLoader{st: st(), l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OAuth2(tt.initFns...); !cmp.Equal(got, tt.want, equateOAuthLoader) {
				t.Errorf("OAuth2() = %s", cmp.Diff(tt.want, got, equateOAuthLoader))
			}
		})
	}
}

func areOAuthLoader(a, b any) bool {
	_, ok1 := a.(oauthLoader)
	_, ok2 := b.(oauthLoader)
	return ok1 && ok2
}

func compareOAuthLoader(x, y any) bool {
	xe := x.(oauthLoader)
	ye := y.(oauthLoader)
	xst, _ := xe.st.(oauthStore)
	yst, _ := ye.st.(oauthStore)
	cx := config{
		st: xst,
		l:  xe.l,
	}
	cy := config{
		st: yst,
		l:  ye.l,
	}
	return compareConfig(cx, cy)
}

var equateOAuthLoader = cmp.FilterValues(areOAuthLoader, cmp.Comparer(compareOAuthLoader))

func Test_oauthLoader_Verify(t *testing.T) {
	tests := []struct {
		name    string
		a       oauthLoader
		r       *http.Request
		want    vocab.Actor
		wantErr error
	}{
		{
			name: "nil request",
			a:    oauthLoader{l: lw.Dev(lw.SetOutput(t.Output()))},
			r:    nil,
			want: AnonymousActor,
		},
		{
			name:    "no header",
			a:       oauthLoader{st: st(), l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       mockGetReq(),
			want:    AnonymousActor,
			wantErr: errors.BadRequestf("could not load bearer token from request"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, verifierTest(tt.a, tt.r, tt.want, tt.wantErr))
	}
}

func Test_firstOrItem(t *testing.T) {
	tests := []struct {
		name    string
		it      vocab.Item
		want    vocab.Item
		wantErr error
	}{
		{
			name:    "empty",
			it:      nil,
			want:    nil,
			wantErr: nil,
		},
		{
			name: "iri",
			it:   vocab.IRI("http://example.com/666"),
			want: vocab.IRI("http://example.com/666"),
		},
		{
			name: "object",
			it:   &vocab.Object{ID: "http://example.com/1"},
			want: &vocab.Object{ID: "http://example.com/1"},
		},
		{
			name: "actor",
			it:   &vocab.Actor{ID: "http://example.com/~jdoe"},
			want: &vocab.Actor{ID: "http://example.com/~jdoe"},
		},
		{
			name: "activity",
			it:   &vocab.Activity{ID: "http://example.com/create-1"},
			want: &vocab.Activity{ID: "http://example.com/create-1"},
		},
		{
			name: "item collection",
			it:   vocab.ItemCollection{&vocab.Activity{ID: "http://example.com/create-1"}, vocab.IRI("http://example.com")},
			want: &vocab.Activity{ID: "http://example.com/create-1"},
		},
		{
			name: "ordered collection",
			it: &vocab.OrderedCollection{
				Type:         vocab.OrderedCollectionType, // NOTE(marius): this is needed at the moment
				OrderedItems: vocab.ItemCollection{vocab.IRI("http://example.com"), &vocab.Activity{ID: "http://example.com/create-1"}},
			},
			want: vocab.IRI("http://example.com"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := firstOrItem(tt.it)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("firstOrItem() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("firstOrItem() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func Test_assertToBytes(t *testing.T) {
	tests := []struct {
		name       string
		maybeBytes any
		want       []byte
		wantErr    error
	}{
		{
			name:       "empty",
			maybeBytes: nil,
			want:       nil,
			wantErr:    nil,
		},
		{
			name:       "byte slice",
			maybeBytes: []byte("test"),
			want:       []byte("test"),
		},
		{
			name:       "string",
			maybeBytes: "test-string",
			want:       []byte("test-string"),
		},
		{
			name:       "string",
			maybeBytes: json.RawMessage("test-json-raw-message"),
			want:       []byte("test-json-raw-message"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := assertToBytes(tt.maybeBytes)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("assertToBytes() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("assertToBytes() got = %s, want %s", got, tt.want)
			}
		})
	}
}
