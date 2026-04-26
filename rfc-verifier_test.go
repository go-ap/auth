package auth

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/common-fate/httpsig/sigparams"
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

var ()

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
		PublicKey: mockActorGenKey(vocab.IRI(keyId), iri, prv),
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
func Test_httpSigVerifier_VerifyRFCSignature(t *testing.T) {
	initKeyLoader := func(initFns ...InitFn) httpSigVerifier {
		nonceStore = new(syncedNonceStore)
		c := config{}
		for _, fn := range initFns {
			fn(&c)
		}
		return httpSigVerifier{
			loader: keyLoader{
				c:  c.c,
				st: c.st,
			},
			l: c.l,
		}
	}

	tests := []struct {
		name    string
		opts    *sigparams.ValidateOpts
		initFns []InitFn
		req     *http.Request
		created time.Time
		want    vocab.Actor
		wantErr error
	}{
		{
			name:    "empty",
			req:     nil,
			want:    AnonymousActor,
			wantErr: nil,
		},
		{
			name:    "GET no signature",
			req:     mockGetReq(),
			want:    AnonymousActor,
			wantErr: nil,
		},
		{
			name: "GET w/ no signature-input",
			req: mockGetReq(url.Values{
				"Signature": []string{"invalid"},
			}),
			want:    AnonymousActor,
			wantErr: errors.Newf(`signature "invalid" did not have a corresponding Signature-Input field`),
		},
		{
			name: "GET w/ empty signature-input",
			req: mockGetReq(url.Values{
				"Signature-Input": []string{``},
			}),
			want:    AnonymousActor,
			wantErr: errors.Newf(`no matching signatures`),
		},
		{
			name: "GET w/ invalid signature-input",
			req: mockGetReq(url.Values{
				"Signature-Input": []string{"invalid"},
			}),
			want:    AnonymousActor,
			wantErr: errors.Newf(`could not cast signature input field invalid to a httpsfv.InnerList, got type httpsfv.Item`),
		},
		{
			name: "GET no corresponding signature",
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`empty=()`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Newf(`signature input "empty" had no corresponding signature`),
		},
		{
			name: "GET no timestamp",
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`empty=()`},
				"Signature":       []string{`empty=::`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Newf(`no matching signatures: created timestamp 0001-01-01 00:00:00 +0000 UTC was earlier than earliest allowed value %s`, time.Now().Truncate(time.Second).Add(-time.Minute).UTC()),
		},
		{
			name:    "GET rfc9421 - B.2.1. example, no client",
			created: time.UnixMicro(1618884473 * 1000 * 1000),
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errInvalidClient, "no matching signatures"),
		},
		{
			name:    "GET rfc9421 - B.2.1. example, w/ client",
			created: time.UnixMicro(1618884473 * 1000 * 1000),
			initFns: []InitFn{WithClient(client.New())},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want: AnonymousActor,
			wantErr: errors.Annotatef(
				errors.Annotatef(
					errors.Newf(`Get "test-key-rsa-pss": unsupported protocol scheme ""`),
					"unable to fetch key",
				),
				"no matching signatures",
			),
		},
		{
			name:    "minimal signature using rsa-sha512 example - no nonce",
			created: time.UnixMicro(1618884473 * 1000 * 1000),
			initFns: []InitFn{
				WithClient(client.New()),
				WithStorage(st(mockRFCActor(prvKeyRSA1, "#main"), mockActorGenKey("http://example.com/~jdoe#main", "http://example.com/~jdoe", prvKeyRSA1))),
			},
			req: rfcMockReq(url.Values{
				"Signature-Input": []string{`sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="http://example.com/~jdoe#main";tag="header-example"`},
				"Signature":       []string{`sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf("nonce is required"), "no matching signatures"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := initKeyLoader(tt.initFns...)
			if tt.opts != nil {
				defaultValidationOpts = *tt.opts
			}
			if !tt.created.IsZero() {
				nowFn = func() time.Time {
					return tt.created
				}
			}
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
