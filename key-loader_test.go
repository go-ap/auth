package auth

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dadrus/httpsig"
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
		{
			name: "deleted",
			arg:  "http://example.com/~jdoe#main",
			want: AnonymousActor,
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusGone)
			}),
			wantErr: errors.Gonef("key does not exist"),
		},
		{
			name: "tags.pub actor issue #473",
			arg:  "http://example.com/user/activitypub",
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				payload := `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://purl.archive.org/socialweb/webfinger",
    "https://purl.archive.org/miscellany"
  ],
  "id": "http://example.com/user/activitypub",
  "type": "Service",
  "inbox": "http://example.com/user/activitypub/inbox",
  "webfinger": "activitypub@tags.pub",
  "publicKey": {
    "id": "http://example.com/user/activitypub/publickey",
    "type": "CryptographicKey",
    "owner": "http://example.com/user/activitypub",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
    "to": "as:Public"
  },
  "endpoints": {
    "sharedInbox": "http://example.com/shared/inbox"
  },
  "followers": "http://example.com/user/activitypub/followers",
  "following": "http://example.com/user/activitypub/following",
  "icon": {
    "type": "Link",
    "href": "http://example.com/user/activitypub/icon"
  },
  "liked": "http://example.com/user/activitypub/liked",
  "manuallyApprovesFollowers": false,
  "name": "#activitypub",
  "outbox": "http://example.com/user/activitypub/outbox",
  "preferredUsername": "activitypub",
  "summary": "<p>Follow me if you&apos;re interested in the #activitypub hashtag.</p>",
  "to": "as:Public",
  "url": {
    "type": "Link",
    "href": "http://example.com/profile/activitypub",
    "mediaType": "text/html"
  }
}`
				w.Header().Set("Content-Type", "application/activity+json")
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(payload))
			}),
			want: vocab.Actor{
				ID:        "http://example.com/user/activitypub",
				Type:      vocab.ServiceType,
				Name:      vocab.DefaultNaturalLanguage("#activitypub"),
				Icon:      &vocab.Link{Type: vocab.LinkType, Href: "http://example.com/user/activitypub/icon"},
				Summary:   vocab.DefaultNaturalLanguage("<p>Follow me if you&apos;re interested in the #activitypub hashtag.</p>"),
				URL:       &vocab.Link{Type: vocab.LinkType, MediaType: "text/html", Href: "http://example.com/profile/activitypub"},
				To:        vocab.ItemCollection{vocab.IRI("as:Public")},
				Inbox:     vocab.IRI("http://example.com/user/activitypub/inbox"),
				Outbox:    vocab.IRI("http://example.com/user/activitypub/outbox"),
				Following: vocab.IRI("http://example.com/user/activitypub/following"),
				Followers: vocab.IRI("http://example.com/user/activitypub/followers"),
				Liked:     vocab.IRI("http://example.com/user/activitypub/liked"),
				Endpoints: &vocab.Endpoints{SharedInbox: vocab.IRI("http://example.com/shared/inbox")},
				PublicKey: vocab.PublicKey{
					ID:           "http://example.com/user/activitypub/publickey",
					Owner:        "http://example.com/user/activitypub",
					PublicKeyPem: `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n`,
				},
			},
			wantKey: &vocab.PublicKey{
				ID:           "http://example.com/user/activitypub/publickey",
				Owner:        "http://example.com/user/activitypub",
				PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			name: "tags.pub key issue #473",
			arg:  "http://example.com/user/activitypub/publickey",
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				payload := `{
  "id": "http://example.com/user/activitypub/publickey",
  "type": "CryptographicKey",
  "owner": "http://example.com/user/activitypub",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
  "to": "as:Public"
}`
				w.Header().Set("Content-Type", "application/activity+json")
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(status)
				if !strings.HasSuffix(r.URL.Path, "/publickey") {
					payload = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://purl.archive.org/socialweb/webfinger",
    "https://purl.archive.org/miscellany"
  ],
  "id": "http://example.com/user/activitypub",
  "type": "Service",
  "inbox": "http://example.com/user/activitypub/inbox",
  "webfinger": "activitypub@tags.pub",
  "publicKey": {
    "id": "http://example.com/user/activitypub/publickey",
    "type": "CryptographicKey",
    "owner": "http://example.com/user/activitypub",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
    "to": "as:Public"
  },
  "endpoints": {
    "sharedInbox": "http://example.com/shared/inbox"
  },
  "followers": "http://example.com/user/activitypub/followers",
  "following": "http://example.com/user/activitypub/following",
  "icon": {
    "type": "Link",
    "href": "http://example.com/user/activitypub/icon"
  },
  "liked": "http://example.com/user/activitypub/liked",
  "manuallyApprovesFollowers": false,
  "name": "#activitypub",
  "outbox": "http://example.com/user/activitypub/outbox",
  "preferredUsername": "activitypub",
  "summary": "<p>Follow me if you&apos;re interested in the #activitypub hashtag.</p>",
  "to": "as:Public",
  "url": {
    "type": "Link",
    "href": "http://example.com/profile/activitypub",
    "mediaType": "text/html"
  }
}`
				}
				_, _ = w.Write([]byte(payload))
			}),
			want: vocab.Actor{
				ID:        "http://example.com/user/activitypub",
				Type:      vocab.ServiceType,
				Name:      vocab.DefaultNaturalLanguage("#activitypub"),
				Icon:      &vocab.Link{Type: vocab.LinkType, Href: "http://example.com/user/activitypub/icon"},
				Summary:   vocab.DefaultNaturalLanguage("<p>Follow me if you&apos;re interested in the #activitypub hashtag.</p>"),
				URL:       &vocab.Link{Type: vocab.LinkType, MediaType: "text/html", Href: "http://example.com/profile/activitypub"},
				To:        vocab.ItemCollection{vocab.IRI("as:Public")},
				Inbox:     vocab.IRI("http://example.com/user/activitypub/inbox"),
				Outbox:    vocab.IRI("http://example.com/user/activitypub/outbox"),
				Following: vocab.IRI("http://example.com/user/activitypub/following"),
				Followers: vocab.IRI("http://example.com/user/activitypub/followers"),
				Liked:     vocab.IRI("http://example.com/user/activitypub/liked"),
				Endpoints: &vocab.Endpoints{SharedInbox: vocab.IRI("http://example.com/shared/inbox")},
				PublicKey: vocab.PublicKey{
					ID:           "http://example.com/user/activitypub/publickey",
					Owner:        "http://example.com/user/activitypub",
					PublicKeyPem: `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n`,
				},
			},
			wantKey: &vocab.PublicKey{
				ID:           "http://example.com/user/activitypub/publickey",
				Owner:        "http://example.com/user/activitypub",
				PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
			},
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
			if !cmp.Equal(key, tt.wantKey) {
				t.Errorf("GetKey() got key = %s", cmp.Diff(tt.wantKey, key))
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

func Test_rfcAlgorithmFromPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		pub     vocab.PublicKey
		want    httpsig.SignatureAlgorithm
		wantKey crypto.PublicKey
		wantErr error
	}{
		{
			name:    "empty",
			pub:     vocab.PublicKey{},
			wantErr: errors.Newf("unable to decode PEM payload for public key"),
		},
		{
			name:    "rsa256",
			pub:     mockActorGenKey("test", "test", prvKeyRSA),
			want:    httpsig.RsaPkcs1v15Sha256,
			wantKey: pubKeyRSA,
		},
		{
			name:    "ecdsa256",
			pub:     mockActorGenKey("test", "test", prvKeyECDSA),
			want:    httpsig.EcdsaP256Sha256,
			wantKey: &prvKeyECDSA.PublicKey,
		},
		{
			name:    "ed25519",
			pub:     mockActorGenKey("test", "test", prvKeyEd25519),
			want:    httpsig.Ed25519,
			wantKey: pubKeyEd25519,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, key, err := rfcAlgorithmFromPublicKey(&tt.pub)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("rfcAlgorithmFromPublicKey() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if got != tt.want {
				t.Errorf("rfcAlgorithmFromPublicKey() got = %v, want %v", got, tt.want)
			}
			if !cmp.Equal(key, tt.wantKey, EquatePublicKeys) {
				t.Errorf("rfcAlgorithmFromPublicKey() got1 = %s", cmp.Diff(tt.wantKey, key, EquatePublicKeys))
			}
		})
	}
}
