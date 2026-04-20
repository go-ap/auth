package auth

import (
	"crypto"
	"net/http"
	"reflect"
	"testing"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
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
	srv, _ := testServerWithURL(mockKeyAndActorHandler)

	type fields struct {
		baseURL    string
		iriIsLocal func(vocab.IRI) bool
		ignore     vocab.IRIs
		c          *client.C
		st         oauthStore
		l          lw.Logger
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
				baseURL:    "http://example.com",
				iriIsLocal: isNotLocal,
				c:          cl,
				l:          lw.Dev(lw.SetOutput(t.Output())),
			},
			arg: vocab.IRI(srv.URL + "/~jdoe#main"),
			want: result{
				act: mockActor(srv.URL),
				key: publicKey(vocab.IRI(srv.URL+"/~jdoe#main"), vocab.IRI(srv.URL+"/~jdoe")),
			},
			wantErr: false,
		},
		{
			name: "second request",
			fields: fields{
				baseURL:    "http://example.com",
				iriIsLocal: isNotLocal,
				c:          cl,
				l:          lw.Dev(lw.SetOutput(t.Output())),
			},
			arg: vocab.IRI(srv.URL + "/~jdoe#main"),
			want: result{
				act: mockActor(srv.URL),
				key: publicKey(vocab.IRI(srv.URL+"/~jdoe#main"), vocab.IRI(srv.URL+"/~jdoe")),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := keyLoader{
				iriIsLocal: tt.fields.iriIsLocal,
				ignore:     tt.fields.ignore,
				c:          tt.fields.c,
				st:         tt.fields.st,
				l:          lw.Dev(lw.SetOutput(t.Output())),
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

func Test_keyLoader_GetKey(t *testing.T) {
	srv, _ := testServerWithURL(mockKeyAndActorHandler)
	type result struct {
		act vocab.Actor
		key crypto.PublicKey
	}
	tests := []struct {
		name    string
		arg     string
		want    result
		wantErr error
	}{
		{
			name: "empty",
			want: result{
				act: vocab.Actor{},
				key: (*vocab.PublicKey)(nil),
			},
			wantErr: errors.Newf("empty IRI"),
		},
		{
			name: "remote key IRI as separate resource",
			arg:  srv.URL + "/~jdoe/key",
			want: result{
				act: vocab.Actor{
					ID:   vocab.IRI(srv.URL + "/~jdoe"),
					Type: vocab.PersonType,
					PublicKey: vocab.PublicKey{
						ID:           vocab.IRI(srv.URL + "/~jdoe/key"),
						Owner:        vocab.IRI(srv.URL + "/~jdoe"),
						PublicKeyPem: pemEncodePublicKey(prv),
					},
				},
				key: prv.Public(),
			},
		},
		{
			name: "remote key IRI as actor resource",
			arg:  srv.URL + "/~jdoe#main",
			want: result{
				act: mockActor(srv.URL),
				key: prv.Public(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &keyLoader{
				c: client.New(),
				l: lw.Dev(lw.SetOutput(t.Output())),
				// NOTE(marius): this now looks suspicious
				st: st(tt.want.act),
			}
			act, key, err := k.GetKey(tt.arg)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if !cmp.Equal(act, tt.want.act) {
				t.Errorf("GetKey() got actor = %s", cmp.Diff(tt.want.act, act))
			}
			if !cmp.Equal(key, tt.want.key) {
				t.Errorf("GetKey() got key = %s", cmp.Diff(tt.want.key, key))
			}
		})
	}
}

func TestHTTPSignature(t *testing.T) {
	mockLogger := lw.Dev(lw.SetOutput(t.Output()))
	type args struct {
		cl      *client.C
		initFns []InitFn
	}
	tests := []struct {
		name string
		args args
		want keyLoader
	}{
		{
			name: "empty",
			args: args{},
			want: keyLoader{l: lw.Nil()},
		},
		{
			name: "with logger",
			args: args{cl: nil, initFns: []InitFn{WithLogger(mockLogger)}},
			want: keyLoader{l: mockLogger},
		},
		{
			name: "with ignoreIRIs",
			args: args{cl: nil, initFns: []InitFn{WithIgnoreList(ignoreIRIs...)}},
			want: keyLoader{ignore: ignoreIRIs, l: lw.Nil()},
		},
		{
			name: "with local IRI func",
			args: args{cl: nil, initFns: []InitFn{WithLocalIRIFn(mockLocalIRIFn)}},
			want: keyLoader{iriIsLocal: mockLocalIRIFn, l: lw.Nil()},
		},
		{
			name: "with storage",
			args: args{cl: nil, initFns: []InitFn{WithStorage(st())}},
			want: keyLoader{st: st(), l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPSignature(tt.args.cl, tt.args.initFns...); !cmp.Equal(got, tt.want, equateKeyLoader) {
				t.Errorf("HTTPSignature() = %s", cmp.Diff(tt.want, got, equateKeyLoader))
			}
		})
	}
}

func areKeyLoader(a, b any) bool {
	_, ok1 := a.(keyLoader)
	_, ok2 := b.(keyLoader)
	return ok1 && ok2
}

func compareKeyLoader(x, y any) bool {
	xe := x.(keyLoader)
	ye := y.(keyLoader)
	return compareConfig(config(xe), config(ye))
}

var equateKeyLoader = cmp.FilterValues(areKeyLoader, cmp.Comparer(compareKeyLoader))

func Test_keyLoader_Verify(t *testing.T) {
	tests := []struct {
		name    string
		a       keyLoader
		r       *http.Request
		want    vocab.Actor
		wantErr error
	}{
		{
			name:    "nil request",
			a:       keyLoader{l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       nil,
			want:    AnonymousActor,
			wantErr: errInvalidStorage,
		},
		{
			name:    "no header",
			a:       keyLoader{st: st(), l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       mockReq(),
			want:    AnonymousActor,
			wantErr: errors.NewBadRequest(errors.Newf("neither \"Signature\" nor \"Authorization\" have signature parameters"), "unable to initialize HTTP Signatures verifier"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, verifierTest(tt.a, tt.r, tt.want, tt.wantErr))
	}
}
