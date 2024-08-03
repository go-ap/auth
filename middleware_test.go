package auth

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
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
		Server  *osin.Server
		baseURL string
		account Account
		cl      client.Basic
		st      readStore
		l       lw.Logger
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
				Server:  tt.fields.Server,
				baseURL: tt.fields.baseURL,
				account: tt.fields.account,
				cl:      tt.fields.cl,
				l:       tt.fields.l,
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
