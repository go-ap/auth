package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"git.sr.ht/~mariusor/lw"
	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
)

func Test_syncedNonceStore_Seen(t *testing.T) {
	tests := []struct {
		name         string
		argSequence  []string
		wantSequence []bool
	}{
		{
			name:         "empty",
			argSequence:  []string{""},
			wantSequence: []bool{false},
		},
		{
			name:         "not seen",
			argSequence:  []string{"1"},
			wantSequence: []bool{false},
		},
		{
			name:         "two not seen",
			argSequence:  []string{"1", "2"},
			wantSequence: []bool{false, false},
		},
		{
			name:         "seen",
			argSequence:  []string{"1", "1"},
			wantSequence: []bool{false, true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &syncedNonceStore{
				Map: sync.Map{},
			}
			for i, arg := range tt.argSequence {
				want := tt.wantSequence[i]
				if got := s.Seen(arg); got != want {
					t.Errorf("Seen() = %v, want %v", got, want)
				}
			}
		})
	}
}

// NOTE(marius): these values also come from the Test Cases appendix of RFC9421 HTTP-Signature doc
// https://www.rfc-editor.org/rfc/rfc9421.html#name-test-cases
func rfcMockReq(hh ...url.Values) *http.Request {
	rfcHdrs := url.Values{
		"Date":         []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
		"Content-Type": []string{"application/json"},
		"Digest":       []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
	}
	for _, h := range hh {
		for k, v := range h {
			rfcHdrs[k] = v
		}
	}
	r := mockPostReq([]byte(`{"hello": "world"}`), rfcHdrs)
	r.URL.Path = "/foo"
	r.URL.RawQuery = "param=Value&Pet=dog"
	return r
}

func mockRFCActor(prv privateKey, keyId vocab.IRI) vocab.Actor {
	iri := vocab.IRI("http://example.com/~jdoe")
	return vocab.Actor{
		ID:        iri,
		Type:      vocab.PersonType,
		PublicKey: mockActorGenKey(keyId, iri, prv),
	}
}

type privateKey interface {
	Public() crypto.PublicKey
}

func mockActorGenKey(id, owner vocab.IRI, prv privateKey) vocab.PublicKey {
	pubKey := prv.Public()
	pubEnc, _ := x509.MarshalPKIXPublicKey(pubKey)
	p := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubEnc,
	}

	return vocab.PublicKey{
		ID:           id,
		Owner:        owner,
		PublicKeyPem: string(pem.EncodeToMemory(&p)),
	}
}

type mockLoader struct {
	it vocab.Actor
}

func (m mockLoader) loadKey(_ string) (vocab.Actor, *vocab.PublicKey, error) {
	return m.it, &m.it.PublicKey, nil
}

func (m mockLoader) Actor() vocab.Actor {
	return m.it
}

func (m mockLoader) ResolveKey(_ context.Context, id string) (httpsig.Key, error) {
	key := httpsig.Key{KeyID: string(m.it.PublicKey.ID)}
	pkey, _ := toCryptoPublicKey(m.it.PublicKey)
	switch pk := pkey.(type) {
	case *rsa.PublicKey:
		switch pk.Size() {
		case 256:
			key.Algorithm = httpsig.RsaPkcs1v15Sha256
		case 384:
			key.Algorithm = httpsig.RsaPkcs1v15Sha384
		case 512:
			key.Algorithm = httpsig.RsaPkcs1v15Sha512
		}
		key.Key = pk
	case *ecdsa.PublicKey:
		if p := pk.Params(); p != nil {
			switch p.BitSize {
			case 256:
				key.Algorithm = httpsig.EcdsaP256Sha256
			case 384:
				key.Algorithm = httpsig.EcdsaP384Sha384
			case 512:
				key.Algorithm = httpsig.EcdsaP521Sha512
			}
		}
		key.Key = pk
	case ed25519.PublicKey:
		key.Algorithm = httpsig.Ed25519
		key.Key = pk
	}
	return key, nil
}

func ldr(c ActivityPubClient, st oauthStore) *localRemoteLoader {
	return &localRemoteLoader{c: c, st: st}
}

func mldr(it vocab.Actor) mockLoader {
	return mockLoader{it: it}
}

// NOTE(marius): we need to increase the max age for validation to something that allows
// the date we're using in the tests we got from the RFC: Tue, 20 Apr 2021 02:07:55 GMT
var enoughForOldTests = time.Since(time.UnixMicro(1618880000 * 1000 * 1000))

func Test_httpSigVerifier_VerifyRFCSignature(t *testing.T) {
	tests := []struct {
		name        string
		loader      keyLoader
		req         *http.Request
		sigDuration time.Duration
		want        vocab.Actor
		wantErr     error
	}{
		{
			name:    "empty",
			req:     nil,
			loader:  mockLoader{},
			want:    AnonymousActor,
			wantErr: errInvalidRequest,
		},
		{
			name:    "GET no signature",
			loader:  mockLoader{},
			req:     mockGetReq(),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(new(httpsig.NoApplicableSignatureError), "verification failed"),
		},
		{
			name:   "GET w/ invalid signature-input",
			loader: mockLoader{},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{"invalid"},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(fmt.Errorf("%w: unexpected signature parameters format", httpsig.ErrMalformedData), "verification failed"),
		},
		{
			name:   "GET no corresponding signature",
			loader: mockLoader{},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`empty=()`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(fmt.Errorf("%w: no signature present for label %s", httpsig.ErrMalformedData, "empty"), "verification failed"),
		},
		{
			name:        "GET rfc9421 - B.2.1. example - wrong private key",
			sigDuration: enoughForOldTests,
			loader:      mockLoader{it: mockRFCActor(prvKeyRSA1, "test-key-rsa-pss")},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf("invalid signature: crypto/rsa: verification error"), "verification failed"),
		},
		{
			name:        "GET rfc9421 - B.2.1. example, w/ client",
			sigDuration: enoughForOldTests,
			loader:      ldr(client.New(), nil),
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf("unable to fetch key: test-key-rsa-pss"), "verification failed"),
		},
		{
			name:        "minimal signature using rsa-sha512 example - no content-digest",
			sigDuration: time.Minute,
			loader:      ldr(client.New(), st(mockRFCActor(prvKeyRSA1, "#main"), mockActorGenKey("http://example.com/~jdoe#main", "http://example.com/~jdoe", prvKeyRSA1))),
			req: rfcMockReq(url.Values{
				"Signature-Input": []string{`sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="http://example.com/~jdoe#main";tag="header-example"`},
				"Signature":       []string{`sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(fmt.Errorf("%w: %s not present in message", httpsig.ErrCanonicalization, "content-digest"), "verification failed"),
		},
		{
			name:        "minimal signature using rsa-sha512 example",
			sigDuration: enoughForOldTests,
			loader:      mldr(mockRFCActor(prvKeyEd25519, "test-key-ed25519")),
			req: rfcMockReq(url.Values{
				"Signature-Input": []string{`sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`},
				"Signature":       []string{`sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`},
			}),
			want: mockRFCActor(prvKeyEd25519, "test-key-ed25519"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonceStore = new(syncedNonceStore)
			if tt.sigDuration > 0 {
				sigMaxAgeDuration = tt.sigDuration
			}

			k := httpSigVerifier{loader: tt.loader, l: lw.Dev(lw.SetOutput(t.Output()))}
			got, err := k.VerifyRFCSignature(tt.req)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("VerifyRFCSignature() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("VerifyRFCSignature() got = %s", cmp.Diff(tt.want, got, EquateWeakErrors))
			}
		})
	}
}
