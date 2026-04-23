package auth

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-ap/activitypub"
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

func Test_keyLoader_VerifyRFCSignature(t *testing.T) {
	type fields struct {
	}
	tests := []struct {
		name    string
		req     *http.Request
		created time.Time
		want    activitypub.Actor
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyLoader{}
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
