package auth

import (
	"crypto"
	"reflect"
	"testing"

	vocab "github.com/go-ap/activitypub"
	"github.com/google/go-cmp/cmp"
)

func publicKey(id, owner vocab.IRI) *vocab.PublicKey {
	return &vocab.PublicKey{
		ID:           id,
		Owner:        owner,
		PublicKeyPem: pemEncodePublicKey(prv),
	}
}

func Test_keyLoader_LoadActorFromKeyIRI(t *testing.T) {
	type fields struct {
		baseURL    string
		iriIsLocal func(vocab.IRI) bool
		ignore     vocab.IRIs
		c          Client
		st         oauthStore
		l          LoggerFn
	}
	type result struct {
		act vocab.Actor
		key crypto.PublicKey
	}
	tests := []struct {
		name    string
		fields  fields
		arg     vocab.IRI
		want    result
		wantErr bool
	}{
		{
			name:   "empty",
			fields: fields{},
			want: result{
				act: AnonymousActor,
				key: (*vocab.PublicKey)(nil),
			},
		},
		{
			name: "first request",
			fields: fields{
				baseURL:    "https://example.com",
				iriIsLocal: isNotLocal,
				c:          cl,
				l:          logFn,
			},
			arg: vocab.IRI(srv.URL + "/jdoe#main"),
			want: result{
				act: mockActor(srv.URL),
				key: publicKey(vocab.IRI(srv.URL+"/jdoe#main"), vocab.IRI(srv.URL+"/jdoe")),
			},
			wantErr: false,
		},
		{
			name: "second request",
			fields: fields{
				baseURL:    "https://example.com",
				iriIsLocal: isNotLocal,
				c:          cl,
				l:          logFn,
			},
			arg: vocab.IRI(srv.URL + "/jdoe#main"),
			want: result{
				act: mockActor(srv.URL),
				key: publicKey(vocab.IRI(srv.URL+"/jdoe#main"), vocab.IRI(srv.URL+"/jdoe")),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := keyLoader{
				baseURL:    tt.fields.baseURL,
				iriIsLocal: tt.fields.iriIsLocal,
				ignore:     tt.fields.ignore,
				c:          tt.fields.c,
				st:         tt.fields.st,
				logFn:      tt.fields.l,
			}
			act, key, err := a.LoadActorFromKeyIRI(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadActorFromKeyIRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(act, tt.want.act) {
				t.Errorf("LoadActorFromKeyIRI() got actor = %s", cmp.Diff(tt.want.act, act))
			}
			if !cmp.Equal(key, tt.want.key) {
				t.Errorf("LoadActorFromKeyIRI() got key = %s", cmp.Diff(tt.want.key, key))
			}
		})
	}
}
