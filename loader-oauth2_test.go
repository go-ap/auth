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
		ID:   vocab.IRI(base + "/~jdoe"),
		Type: vocab.PersonType,
		PublicKey: vocab.PublicKey{
			ID:           vocab.IRI(base + "/~jdoe#main"),
			Owner:        vocab.IRI(base + "/~jdoe"),
			PublicKeyPem: pemEncodePublicKey(prv),
		},
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

func testServerWithURL(handler func(string) http.Handler) (*httptest.Server, error) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ts := httptest.NewUnstartedServer(nil)
	ts.Listener = l
	ts.Config.Handler = handler(fmt.Sprintf("http://%s", ts.Listener.Addr().String()))

	ts.Start()
	return ts, nil
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
	type args struct {
		cl      *client.C
		initFns []InitFn
	}
	tests := []struct {
		name string
		args args
		want oauthLoader
	}{
		{
			name: "empty",
			args: args{},
			want: oauthLoader{l: lw.Nil()},
		},
		{
			name: "with logger",
			args: args{cl: nil, initFns: []InitFn{WithLogger(mockLogger)}},
			want: oauthLoader{l: mockLogger},
		},
		{
			name: "with ignoreIRIs",
			args: args{cl: nil, initFns: []InitFn{WithIgnoreList(ignoreIRIs...)}},
			want: oauthLoader{ignore: ignoreIRIs, l: lw.Nil()},
		},
		{
			name: "with local IRI func",
			args: args{cl: nil, initFns: []InitFn{WithLocalIRIFn(mockLocalIRIFn)}},
			want: oauthLoader{iriIsLocal: mockLocalIRIFn, l: lw.Nil()},
		},
		{
			name: "with storage",
			args: args{cl: nil, initFns: []InitFn{WithStorage(st())}},
			want: oauthLoader{st: st(), l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OAuth2(tt.args.cl, tt.args.initFns...); !cmp.Equal(got, tt.want, equateOAuthLoader) {
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
	return compareConfig(config(xe), config(ye))
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
			r:       mockReq(),
			want:    AnonymousActor,
			wantErr: errors.BadRequestf("could not load bearer token from request"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, verifierTest(tt.a, tt.r, tt.want, tt.wantErr))
	}
}
