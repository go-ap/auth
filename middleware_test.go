package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-ap/client"
	"github.com/go-ap/jsonld"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/openshift/osin"
)

func TestKeyLoader_GetKey(t *testing.T) {
	t.Skipf("TODO")
}

func TestOauthLoader_Verify(t *testing.T) {
	t.Skipf("TODO")
}

func TestActorContext(t *testing.T) {
	t.Skipf("TODO")
}

func TestServer_LoadActorFromRequest(t *testing.T) {
	type fields struct {
		Server    *osin.Server
		localURLs vocab.IRIs
		account   Account
		cl        Client
		st        readStore
		l         lw.Logger
	}
	tests := []struct {
		name    string
		fields  fields
		header  string
		want    vocab.Actor
		wantErr bool
	}{
		{
			name:    "empty",
			fields:  fields{},
			header:  "",
			want:    AnonymousActor,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				Server:    tt.fields.Server,
				localURLs: tt.fields.localURLs,
				account:   tt.fields.account,
				cl:        tt.fields.cl,
				l:         tt.fields.l,
			}
			r := http.Request{Header: http.Header{}, URL: new(url.URL)}
			r.Header.Set("Authorization", tt.header)
			got, err := s.LoadActorFromRequest(&r)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadActorFromRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadActorFromRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

var ll = lw.Dev()
var cl = client.New(
	client.WithLogger(ll.WithContext(lw.Ctx{"log": "client"})),
	client.SkipTLSValidation(true),
)

var logFn LoggerFn = func(ctx lw.Ctx, msg string, p ...interface{}) {
	ll.WithContext(ctx).Debugf(msg, p...)
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

func mockActor(base string) *vocab.Actor {
	return &vocab.Actor{
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

func Test_keyLoader_GetKey(t *testing.T) {
	loadActorFromKeyFn := (actorResolver{c: cl, l: logFn, iriIsLocal: isNotLocal}).LoadActorFromKeyIRI
	tests := []struct {
		name    string
		arg     string
		want    crypto.PublicKey
		wantErr bool
	}{
		//{
		//	name:    "empty",
		//	wantErr: true,
		//},
		//{
		//	name:    "remote key IRI as separate resource",
		//	arg:     srv.URL + "/jdoe/key",
		//	want:    prv.Public(),
		//	wantErr: false,
		//},
		{
			name:    "remote key IRI as actor resource",
			arg:     srv.URL + "/jdoe#main",
			want:    prv.Public(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &keyLoader{
				loadActorFromKeyFn: loadActorFromKeyFn,
				logFn:              logFn,
			}
			got, err := k.GetKey(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
