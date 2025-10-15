package auth

import (
	"reflect"
	"testing"

	vocab "github.com/go-ap/activitypub"
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
	tests := []struct {
		name    string
		fields  fields
		arg     vocab.IRI
		want    *vocab.Actor
		want1   *vocab.PublicKey
		wantErr bool
	}{
		{
			name:   "empty",
			fields: fields{},
			want:   &AnonymousActor,
		},
		{
			name: "first request",
			fields: fields{
				baseURL:    "https://example.com",
				iriIsLocal: isNotLocal,
				c:          cl,
				l:          logFn,
			},
			arg:     vocab.IRI(srv.URL + "/jdoe#main"),
			want:    mockActor(srv.URL),
			want1:   publicKey(vocab.IRI(srv.URL+"/jdoe#main"), vocab.IRI(srv.URL+"/jdoe")),
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
			arg:     vocab.IRI(srv.URL + "/jdoe#main"),
			want:    mockActor(srv.URL),
			want1:   publicKey(vocab.IRI(srv.URL+"/jdoe#main"), vocab.IRI(srv.URL+"/jdoe")),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := keyLoader{
				config: config{
					baseURL:    tt.fields.baseURL,
					iriIsLocal: tt.fields.iriIsLocal,
					ignore:     tt.fields.ignore,
					c:          tt.fields.c,
					st:         tt.fields.st,
					logFn:      tt.fields.l,
				},
			}
			got, got1, err := a.LoadActorFromKeyIRI(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadActorFromKeyIRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadActorFromKeyIRI() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("LoadActorFromKeyIRI() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
