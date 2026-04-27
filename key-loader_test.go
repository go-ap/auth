package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"github.com/google/go-cmp/cmp"
)

func Test_keyLoader_loadKey(t *testing.T) {
	tests := []struct {
		name      string
		storage   oauthStore
		arg       string
		handlerFn http.HandlerFunc
		want      vocab.Actor
		wantKey   *vocab.PublicKey
		wantErr   error
	}{
		{
			name:    "empty",
			wantErr: errEmptyIRI,
			want:    AnonymousActor,
		},
		{
			name:    "actor exists locally",
			storage: st(mockActor()),
			arg:     "http://example.com/~jdoe",
			want:    mockActor(),
			wantKey: publicKey("http://example.com/~jdoe#main", "http://example.com/~jdoe"),
		},
		{
			name:    "remote actor",
			arg:     "http://example.com/~jdoe#main",
			want:    mockActor(),
			wantKey: publicKey("http://example.com/~jdoe#main", "http://example.com/~jdoe"),
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				actor := mockActor()
				payload, _ := jsonld.Marshal(actor)

				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(status)
				_, _ = w.Write(payload)
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handlerFn)
			k := &localRemoteLoader{
				c:  client.New(client.WithHTTPClient(srv.Client())),
				st: tt.storage,
			}

			act, key, err := k.loadKey(tt.arg)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Fatalf("Load() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(act, tt.want, EquateItems) {
				t.Errorf("GetKey() got actor = %s", cmp.Diff(tt.want, act, EquateItems))
			}
			if !cmp.Equal(key, tt.wantKey, EquatePublicKeys) {
				t.Errorf("GetKey() got key = %s", cmp.Diff(tt.wantKey, key, EquatePublicKeys))
			}
		})
	}
}

func Test_keyLoader_loadRemoteKey(t *testing.T) {
	tests := []struct {
		name      string
		storage   oauthStore
		arg       vocab.IRI
		handlerFn http.HandlerFunc
		want      vocab.Actor
		wantKey   *vocab.PublicKey
		wantErr   error
	}{
		{
			name:    "empty",
			wantErr: errEmptyIRI,
			want:    AnonymousActor,
		},
		{
			name: "remote key IRI as separate resource",
			arg:  "http://example.com/~jdoe/key",
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor()
				actor.PublicKey.ID = "http://example.com/~jdoe/key"

				payload, _ := vocab.MarshalJSON(actor)
				if strings.HasSuffix(r.URL.Path, "/key") {
					payload, _ = jsonld.Marshal(actor.PublicKey)
				}

				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			}),
			want: vocab.Actor{
				ID:   vocab.IRI("http://example.com/~jdoe"),
				Type: vocab.PersonType,
				PublicKey: vocab.PublicKey{
					ID:           vocab.IRI("http://example.com/~jdoe/key"),
					Owner:        vocab.IRI("http://example.com/~jdoe"),
					PublicKeyPem: pemEncodePublicKey(prv),
				},
			},
			wantKey: publicKey("http://example.com/~jdoe/key", "http://example.com/~jdoe"),
		},
		{
			name:    "remote key IRI as actor resource",
			arg:     "http://example.com/~jdoe#main",
			want:    mockActor(),
			wantKey: publicKey("http://example.com/~jdoe#main", "http://example.com/~jdoe"),
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				actor := mockActor()
				payload, _ := jsonld.Marshal(actor)

				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(status)
				_, _ = w.Write(payload)
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handlerFn)
			k := &localRemoteLoader{
				c:  client.New(client.WithHTTPClient(srv.Client())),
				st: tt.storage,
			}

			act, key, err := k.loadRemoteKey(tt.arg)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Fatalf("Load() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(act, tt.want, EquateItems) {
				t.Errorf("GetKey() got actor = %s", cmp.Diff(tt.want, act, EquateItems))
			}
			if !cmp.Equal(key, tt.wantKey, EquatePublicKeys) {
				t.Errorf("GetKey() got key = %s", cmp.Diff(tt.wantKey, key, EquatePublicKeys))
			}
		})
	}
}

func publicKey(id, owner vocab.IRI) *vocab.PublicKey {
	return &vocab.PublicKey{
		ID:           id,
		Owner:        owner,
		PublicKeyPem: pemEncodePublicKey(prv),
	}
}

func Test_keyLoader_loadLocalKey(t *testing.T) {
	type fields struct {
		c  ActivityPubClient
		st readStore
	}
	tests := []struct {
		name    string
		fields  fields
		iri     vocab.IRI
		want    vocab.Actor
		wantKey *vocab.PublicKey
		wantErr error
	}{
		{
			name:    "empty",
			fields:  fields{},
			iri:     "",
			want:    AnonymousActor,
			wantErr: errInvalidStorage,
		},
		{
			name: "not found",
			fields: fields{
				st: st(),
			},
			iri:     "http://example.com/~jdoe",
			want:    AnonymousActor,
			wantErr: errors.NotFoundf("not found"),
		},
		{
			name: "found actor by key iri",
			fields: fields{
				st: st(mockActor()),
			},
			iri:     "http://example.com/~jdoe#main",
			want:    mockActor(),
			wantKey: publicKey("http://example.com/~jdoe#main", "http://example.com/~jdoe"),
		},
		{
			name: "found actor",
			fields: fields{
				st: st(mockActor()),
			},
			iri:     "http://example.com/~jdoe",
			want:    mockActor(),
			wantKey: publicKey("http://example.com/~jdoe#main", "http://example.com/~jdoe"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := localRemoteLoader{
				c:  tt.fields.c,
				st: tt.fields.st,
			}
			got, key, err := k.loadLocalKey(tt.iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("loadLocalKey() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("loadLocalKey() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
			if !cmp.Equal(key, tt.wantKey, EquatePublicKeys) {
				t.Errorf("loadLocalKey() got1 = %s", cmp.Diff(tt.wantKey, key, EquatePublicKeys))
			}
		})
	}
}
