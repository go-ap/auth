//go:debug rsa1024min=0
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"git.sr.ht/~mariusor/lw"
	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/client/s2s"
	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
)

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
	it  vocab.Actor
	alg s2s.KeyEncoding
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
			switch m.alg {
			case s2s.KeyTypePSS:
				key.Algorithm = httpsig.RsaPssSha256
			default:
				key.Algorithm = httpsig.RsaPkcs1v15Sha256
			}
		case 384:
			switch m.alg {
			case s2s.KeyTypePSS:
				key.Algorithm = httpsig.RsaPssSha384
			default:
				key.Algorithm = httpsig.RsaPkcs1v15Sha384
			}
		case 512:
			switch m.alg {
			case s2s.KeyTypePSS:
				key.Algorithm = httpsig.RsaPssSha512
			default:
				key.Algorithm = httpsig.RsaPkcs1v15Sha512
			}
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

func mldr(it vocab.Actor, alg s2s.KeyEncoding) mockLoader {
	return mockLoader{it: it, alg: alg}
}

// NOTE(marius): we need to increase the max age for validation to something that allows
// the date we're using in the tests we got from the RFC: Tue, 20 Apr 2021 02:07:55 GMT
var enoughForOldTests = time.Since(time.UnixMicro(1618880000 * 1000 * 1000))

type funcKeyLoader func(string) (vocab.Actor, *vocab.PublicKey, error)

func (fn funcKeyLoader) loadKey(id string) (vocab.Actor, *vocab.PublicKey, error) {
	return fn(id)
}

func (fn funcKeyLoader) Actor() vocab.Actor {
	act, _, _ := fn("")
	return act
}

func (fn funcKeyLoader) ResolveKey(_ context.Context, keyID string) (httpsig.Key, error) {
	_, pk, err := fn(keyID)
	if err != nil {
		return httpsig.Key{}, err
	}
	key := httpsig.Key{KeyID: string(pk.ID)}
	pkey, _ := toCryptoPublicKey(*pk)
	switch pk := pkey.(type) {
	case *rsa.PublicKey:
		switch pk.Size() {
		case 64, 256:
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
	return key, err
}

var (
	raw = []byte{
		// RSA secret key:
		// 3082013b020100024100e221e7c6506e8e3932e66fbf59cc580cd3ccdf688213426f1264144143d58e3d2c478d1cc93a1ab3c1c94cfc927e32f077fa6eb6fe0d59bb656e1c7613b1d53b020301000102404394a271f023ba3979eec842c5917e57070d594f2060a52010bcfc18ad2f2b7ca8b39e75179bd5abb3d161c8c0fe9053cd8de87ae84dd9dc3a84a2749040c261022100e3fd1ddb28613f9ead9869b392fa1f9d91bef1ab625605c968c72f5312ac77b3022100fdea673212cf6da2b1277b736a3b9f04662bb993d8754b1516e9a03010b6e85902205f1a54fbf8aa2869beac575b6b321f42116bff4fa8a38da268acbe16ff31267502210096da64650377e912f75d15a3044257bf2d545cf4d16d1e26716e6b9522d90841022100a960c9d14d424fb58de781aa700d8a838a46e5978cc74dcfdfb9dc16edfcf1ee
		0x30, 0x82, 0x01, 0x3b, 0x02, 0x01, 0x00, 0x02, 0x41, 0x00, 0xe2, 0x21,
		0xe7, 0xc6, 0x50, 0x6e, 0x8e, 0x39, 0x32, 0xe6, 0x6f, 0xbf, 0x59, 0xcc,
		0x58, 0x0c, 0xd3, 0xcc, 0xdf, 0x68, 0x82, 0x13, 0x42, 0x6f, 0x12, 0x64,
		0x14, 0x41, 0x43, 0xd5, 0x8e, 0x3d, 0x2c, 0x47, 0x8d, 0x1c, 0xc9, 0x3a,
		0x1a, 0xb3, 0xc1, 0xc9, 0x4c, 0xfc, 0x92, 0x7e, 0x32, 0xf0, 0x77, 0xfa,
		0x6e, 0xb6, 0xfe, 0x0d, 0x59, 0xbb, 0x65, 0x6e, 0x1c, 0x76, 0x13, 0xb1,
		0xd5, 0x3b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x40, 0x43, 0x94, 0xa2,
		0x71, 0xf0, 0x23, 0xba, 0x39, 0x79, 0xee, 0xc8, 0x42, 0xc5, 0x91, 0x7e,
		0x57, 0x07, 0x0d, 0x59, 0x4f, 0x20, 0x60, 0xa5, 0x20, 0x10, 0xbc, 0xfc,
		0x18, 0xad, 0x2f, 0x2b, 0x7c, 0xa8, 0xb3, 0x9e, 0x75, 0x17, 0x9b, 0xd5,
		0xab, 0xb3, 0xd1, 0x61, 0xc8, 0xc0, 0xfe, 0x90, 0x53, 0xcd, 0x8d, 0xe8,
		0x7a, 0xe8, 0x4d, 0xd9, 0xdc, 0x3a, 0x84, 0xa2, 0x74, 0x90, 0x40, 0xc2,
		0x61, 0x02, 0x21, 0x00, 0xe3, 0xfd, 0x1d, 0xdb, 0x28, 0x61, 0x3f, 0x9e,
		0xad, 0x98, 0x69, 0xb3, 0x92, 0xfa, 0x1f, 0x9d, 0x91, 0xbe, 0xf1, 0xab,
		0x62, 0x56, 0x05, 0xc9, 0x68, 0xc7, 0x2f, 0x53, 0x12, 0xac, 0x77, 0xb3,
		0x02, 0x21, 0x00, 0xfd, 0xea, 0x67, 0x32, 0x12, 0xcf, 0x6d, 0xa2, 0xb1,
		0x27, 0x7b, 0x73, 0x6a, 0x3b, 0x9f, 0x04, 0x66, 0x2b, 0xb9, 0x93, 0xd8,
		0x75, 0x4b, 0x15, 0x16, 0xe9, 0xa0, 0x30, 0x10, 0xb6, 0xe8, 0x59, 0x02,
		0x20, 0x5f, 0x1a, 0x54, 0xfb, 0xf8, 0xaa, 0x28, 0x69, 0xbe, 0xac, 0x57,
		0x5b, 0x6b, 0x32, 0x1f, 0x42, 0x11, 0x6b, 0xff, 0x4f, 0xa8, 0xa3, 0x8d,
		0xa2, 0x68, 0xac, 0xbe, 0x16, 0xff, 0x31, 0x26, 0x75, 0x02, 0x21, 0x00,
		0x96, 0xda, 0x64, 0x65, 0x03, 0x77, 0xe9, 0x12, 0xf7, 0x5d, 0x15, 0xa3,
		0x04, 0x42, 0x57, 0xbf, 0x2d, 0x54, 0x5c, 0xf4, 0xd1, 0x6d, 0x1e, 0x26,
		0x71, 0x6e, 0x6b, 0x95, 0x22, 0xd9, 0x08, 0x41, 0x02, 0x21, 0x00, 0xa9,
		0x60, 0xc9, 0xd1, 0x4d, 0x42, 0x4f, 0xb5, 0x8d, 0xe7, 0x81, 0xaa, 0x70,
		0x0d, 0x8a, 0x83, 0x8a, 0x46, 0xe5, 0x97, 0x8c, 0xc7, 0x4d, 0xcf, 0xdf,
		0xb9, 0xdc, 0x16, 0xed, 0xfc, 0xf1, 0xee,
	}
	mitraPrv, _ = x509.ParsePKCS1PrivateKey(raw)

	mitraActor = vocab.Actor{
		ID: "https://signer.example/actor",
		PublicKey: vocab.PublicKey{
			ID:           "https://signer.example/actor#main-key",
			Owner:        "https://signer.example/actor",
			PublicKeyPem: pemEncodePublicKey(mitraPrv),
		},
	}

	mitraActorDoc = `{"@context":["https://www.w3.org/ns/activitystreams","https://www.w3.org/ns/cid/v1","https://w3id.org/security/v1","https://w3id.org/security/data-integrity/v2",{"manuallyApprovesFollowers":"as:manuallyApprovesFollowers","schema":"http://schema.org/","PropertyValue":"schema:PropertyValue","value":"schema:value","toot":"http://joinmastodon.org/ns#","discoverable":"toot:discoverable","featured":"toot:featured","Emoji":"toot:Emoji","mitra":"http://jsonld.mitra.social#","subscribers":"mitra:subscribers","VerifiableIdentityStatement":"mitra:VerifiableIdentityStatement","MitraJcsEip191Signature2022":"mitra:MitraJcsEip191Signature2022","gateways":"mitra:gateways","implements":"mitra:implements","proofValue":"sec:proofValue","proofPurpose":"sec:proofPurpose"}],"id":"https://mitra.social/users/silverpill","type":"Person","preferredUsername":"silverpill","name":"silverpill","inbox":"https://mitra.social/users/silverpill/inbox","outbox":"https://mitra.social/users/silverpill/outbox","followers":"https://mitra.social/users/silverpill/followers","following":"https://mitra.social/users/silverpill/following","subscribers":"https://mitra.social/users/silverpill/subscribers","featured":"https://mitra.social/users/silverpill/collections/featured","assertionMethod":[{"id":"https://mitra.social/users/silverpill#main-key","type":"Multikey","controller":"https://mitra.social/users/silverpill","publicKeyMultibase":"z4MXj1wBzi9jUstyPkUpxMpTJw8gwWSku9DQGbjZDXXjBf1HpRQGkxugs1aRS6Zx5TvKNj1GrssZSf2Mi855Xq3b5YYSySXNcaiUFC4W6FJbseASFFJpVGpab5toa9q51A37T5zQiDaVZcgi3bsAd27ZpQGkzJn78gh2jJt3ucrYPQ4Mg7ufWkUdPAsko9MTk7hdRUteythAEZFFHb5LmsQJ5dR2a8yfsNH98LvN9iVpmF7cy53SX61gCB8kvk5AdQdzm3BgDWUsjus5BKCwLhPveiRq1cvQmisTrz4Zzc5iHWdp2vtf9qiEcKAqfGhNSsf4ZHP9rdT4p2gV8XM7RbsaTKoo3rmjn9u4QTs3ubdZRr5CMyqkc"},{"id":"https://mitra.social/users/silverpill#ed25519-key","type":"Multikey","controller":"https://mitra.social/users/silverpill","publicKeyMultibase":"z6MkjtdL1hhAtJDRTti4JZtjGVkMiqbrQWhLQjK8wV4neCvS"}],"publicKey":{"id":"https://mitra.social/users/silverpill#main-key","owner":"https://mitra.social/users/silverpill","publicKeyPem":"-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwvnkkLAnX7SThHEC9tOX\ny6Y4N5DjFH4hs1q3VuRJH6NIZbIX3g7EX2yta3WXpJFrvRvfx/39+aYfxGBEP6qr\n0hoa7rYDVWMs/tgsd98Zc4K6dEAlTljvATlGEuW6MDaF9qBM9SIFs0ZFXH90wStD\nhW9PBFcmLpqQ8ZTa+busK0hP/k5PxrmQz18DQpRzdHK0cFK81STAmK/Rrx1uWQRs\nWJvKZHWmhAVZcdDIRLciERx+W4XYFXpl57LkyP6QGpeD+6dGMzt8KR2O9kNBSuAh\njXPQMvzlsK7jLP97+780vyQvTYOCapBzCTOjuPANH0OA7XVR2iv/tVDKSeqC/+p7\ndwIDAQAB\n-----END RSA PUBLIC KEY-----\n"},"generator":{"type":"Application","implements":[{"name":"RFC-9421: HTTP Message Signatures","href":"https://datatracker.ietf.org/doc/html/rfc9421"},{"name":"RFC-9421 signatures using the Ed25519 algorithm","href":"https://datatracker.ietf.org/doc/html/rfc9421#name-eddsa-using-curve-edwards25"}]},"icon":{"type":"Image","url":"https://mitra.social/media/6a785bf7dd05f61c3590e8935aa49156a499ac30fd1e402f79e7e164adb36e2c.png","mediaType":"image/png"},"summary":"<p>Developer of ActivityPub-based micro-blogging and content subscription platform <a href=\"https://codeberg.org/silverpill/mitra\" rel=\"noopener\">Mitra</a>. I help maintain the <a href=\"https://codeberg.org/fediverse/fep\" rel=\"noopener\">FEP repository</a> and write my own <a href=\"https://codeberg.org/silverpill/feps\" rel=\"noopener\">FEPs</a> too. Currently working on <a href=\"https://codeberg.org/ap-next/ap-next\" rel=\"noopener\">ActivityPub Next</a>.</p>","attachment":[{"alsoKnownAs":"https://mitra.social/users/silverpill","proof":{"created":"2024-09-27T15:20:32.266850026Z","proofPurpose":"assertionMethod","proofValue":"zK43vnqGDEMNqEtKe7QJWnVeqhmsRY9NAQKL9XxT7nhjBbTNz1FFB1nLxAaazjMDRirFiQovzYRkaSje5rhzv4XF4w","type":"MitraJcsEip191Signature2022","verificationMethod":"did:pkh:eip155:1:0x198ad1c900a575068879d5b0aabacbfefac522fa"},"subject":"did:pkh:eip155:1:0x198ad1c900a575068879d5b0aabacbfefac522fa","type":"VerifiableIdentityStatement"},{"alsoKnownAs":"https://mitra.social/users/silverpill","proof":{"created":"2026-03-31T17:26:57.650227665Z","cryptosuite":"eddsa-jcs-2022","proofPurpose":"assertionMethod","proofValue":"z5Croj8RckNeLHQjYSEZE9kb2VzGzBaCHwnqqhv79cd37ZPGirrtyGrJkh4tKWxyL7vgnhuJSGhhQxZYnu9wMBJzc","type":"DataIntegrityProof","verificationMethod":"did:key:z6MkrJ9F3pUkBV28cAQ1LNhUmMHakZsx3GLg2eYgyHDv9tnT#z6MkrJ9F3pUkBV28cAQ1LNhUmMHakZsx3GLg2eYgyHDv9tnT"},"subject":"did:key:z6MkrJ9F3pUkBV28cAQ1LNhUmMHakZsx3GLg2eYgyHDv9tnT","type":"VerifiableIdentityStatement"},{"href":"https://mitra.social/users/silverpill/proposals/monero:418015bb9ae982a1975da7d79277c270","mediaType":"application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"","name":"MoneroSubscription","rel":["payment","https://w3id.org/valueflows/ont/vf#Proposal"],"type":"Link"},{"name":"Code","type":"PropertyValue","value":"<a href=\"https://codeberg.org/silverpill/\" rel=\"noopener\">https://codeberg.org/silverpill/</a>"},{"name":"Matrix","type":"PropertyValue","value":"@silverpill:unredacted.org"},{"name":"XMPP","type":"PropertyValue","value":"<a href=\"xmpp:silverpill@were.chat\" rel=\"noopener\">silverpill@were.chat</a>"},{"name":"$XMR","type":"PropertyValue","value":"48YM8jwJqDkeUvD38vepSXFeMZH1zsjbvGwTTuaNSSq6Q5GyeWaeiheAZUsSmNn72YdyLpw8geb4FL3opZfGbguJLUj8Mi9"},{"name":"XMR subscription","type":"PropertyValue","value":"<a href=\"https://mitra.social/@silverpill/subscription\" rel=\"noopener\">https://mitra.social/@silverpill/subscription</a>"},{"name":"PGP","type":"PropertyValue","value":"0541 49E3 0F91 C6D7 8FFA  C49C 955F 5A6E 2123 25F0"},{"name":"OMEMO fingerprint","type":"PropertyValue","value":"689a2fb0ec87a9481fb45cb7d8870da6aeb4d8247bd69a39017701133b901f04"},{"name":"Matrix (backup)","type":"PropertyValue","value":"@silverpill:poa.st"}],"manuallyApprovesFollowers":false,"discoverable":true,"url":"https://mitra.social/users/silverpill","published":"2021-11-06T21:08:57.441927Z","updated":"2026-03-31T17:28:19.959176Z"}`
	mitraActorFn  = func() vocab.Actor {
		it, err := vocab.UnmarshalJSON([]byte(mitraActorDoc))
		if err != nil {
			panic(err)
		}
		a, err := vocab.ToActor(it)
		if err != nil {
			panic(err)
		}
		return *a
	}()

	tagsPubKeyDoc = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://www.w3.org/ns/activitystreams"
  ],
  "id": "https://tags.pub/user/activitypub/publickey",
  "type": "CryptographicKey",
  "owner": "https://tags.pub/user/activitypub",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U5c7F2cpNTKoOz4Pp+g\nThvIMxux3mVtnT58uZv94kzzdL8s+b6ldpuxIN7x+7RmfovWyeKsaot2nM8NWaTZ\nbAVJyCdL1IJ+tTBmeTvtPCKXUuP3xG9qJSFqUPyxEymdVrpdG1uOON6s7p8BVz94\nrMCoKIzUO90pcAV9GTayh2ilTEGHyZW8WEwIZOv9JruPDMBfCiq8LTIDTHGkTXzg\nrU3xfmUjYEt2+McKlEJsh5NL6cZyoPRdI1Ci0whO6UNSNolJxRfuw7Y5EIt6xpqI\nWHkRWAOovE9f4yNAvVNG1SP+6nwjK9tTvAP670QP4RsSS5x/wxcN6mQE1yWjkX9e\ncwIDAQAB\n-----END PUBLIC KEY-----\n",
  "to": "as:Public"
}`

	emptyActorWithTagsPubKeyFn = func() vocab.Actor {
		key := vocab.PublicKey{}
		err := json.Unmarshal([]byte(tagsPubKeyDoc), &key)
		if err != nil {
			panic(err)
		}
		return vocab.Actor{PublicKey: key}
	}()
)

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
			loader:      mockLoader{it: mockRFCActor(prvKeyRSA1, "test-key-rsa-pss"), alg: s2s.KeyTypePSS},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Annotatef(errors.Newf("invalid signature: crypto/rsa: verification error"), "verification failed"), "actor IRI http://example.com/~jdoe"),
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
			loader:      mldr(mockRFCActor(prvKeyEd25519, "test-key-ed25519"), s2s.KeyTypeUnknown),
			req: rfcMockReq(url.Values{
				"Signature-Input": []string{`sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`},
				"Signature":       []string{`sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`},
			}),
			want: mockRFCActor(prvKeyEd25519, "test-key-ed25519"),
		},
		{
			name: "mitra failing example",
			loader: funcKeyLoader(func(id string) (vocab.Actor, *vocab.PublicKey, error) {
				return mitraActor, &mitraActor.PublicKey, nil
			}),
			req: func() *http.Request {
				//request method: POST
				//request body: {}
				//request URI: https://verifier.example/inbox
				//created: 1778314593
				//content-digest header: sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
				//signature header: sig1=:gJWUQjvkEcdXc86ZC+kEWKhUyiExKQomXxWd9q8mzDSm9fE6XjsA+HCoNE9LP4RRCdwAHWZ6Zeou4WPjhxpPwQ==:
				//signature-input header: sig1=("@method" "@target-uri" "content-digest");keyid="https://signer.example/actor#main-key";created=1778314593;alg="rsa-v1_5-sha256"
				// ----
				//signature base:
				// "@method": POST
				// "@target-uri": https://verifier.example/inbox
				// "content-digest": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
				// "@signature-params": ("@method" "@target-uri" "content-digest");keyid="https://signer.example/actor#main-key";created=1778314593;alg="rsa-v1_5-sha256"
				// ----
				// Signature base received from the library
				// "@method": POST
				// "@target-uri": https://verifier.example/inbox
				// "content-digest": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:
				// "@signature-params": ("@method" "@target-uri" "content-digest");keyid="https://signer.example/actor#main-key";created=1778314593;alg="rsa-v1_5-sha256"
				req := httptest.NewRequest(http.MethodPost, "https://verifier.example/inbox", strings.NewReader("{}"))
				req.Header.Add("Content-Digest", "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:")
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest");keyid="https://signer.example/actor#main-key";created=1778314593;alg="rsa-v1_5-sha256"`)
				req.Header.Add("Signature", "sig1=:gJWUQjvkEcdXc86ZC+kEWKhUyiExKQomXxWd9q8mzDSm9fE6XjsA+HCoNE9LP4RRCdwAHWZ6Zeou4WPjhxpPwQ==:")
				return req
			}(),
			sigDuration: 10000 * time.Hour,
			want:        mitraActor,
			wantErr:     nil,
		},
		{
			name:   "mitra prod example",
			loader: mldr(mitraActorFn, s2s.KeyTypePKCS),
			req: func() *http.Request {
				//POST /inbox HTTP/1.1
				//Host: marius.federated.id
				//Accept: */*
				//Accept-Encoding: gzip, br
				//Content-Digest: sha-256=:Ne3sI5+36+54SZkfRoROfH63nbDK84hEikozFWME4fw=:
				//Content-Length: 460
				//Content-Type: application/ld+json; profile="https://www.w3.org/ns/activitystreams"
				//Signature: sig1=:cwLpgfNFKSF2SZfz5eXTRJLuBOOXuzeEV/wbq7Y9i/NACcP8Uyi2iNiwa1QAbeKYunBG3cVplWvXgCVJYwYI241s6t01iKx7tB6upS8hLANlrbHAkY+c0YKfJaPpaWgWZV44k4DEMP47z5AqZVoRCPqGZUvXWuSbMqAy6CAHNiHp9Tb8mZcpZKFuskP+0Lz972I+rwYGdGCd4UGi7tuJZUY8eW99QIHSiBUqXZs5sSmvzi5JxhlKfXhuob6F7f7fUqfj7iMx/A+4EMi9lf/O+uo/P9fZisXOsX65H/T74vlXCXaascia9c7HHiQdbXhrTuoKB9yhNX1sAel7szdiPw==:
				//Signature-Input: sig1=("@method" "@target-uri" "content-digest");keyid="https://mitra.social/users/silverpill#main-key";created=1778251834;alg="rsa-v1_5-sha256"
				//User-Agent: Mitra 5.2.1-dev; https://mitra.social
				//Via: 2.0 Caddy
				//X-Forwarded-For: 162.158.41.180
				//X-Forwarded-Host: marius.federated.id
				//X-Forwarded-Proto: https
				//
				//{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/security/v1","https://w3id.org/security/data-integrity/v2",{"Emoji":"toot:Emoji","Hashtag":"as:Hashtag","sensitive":"as:sensitive","toot":"http://joinmastodon.org/ns#"}],"actor":"https://mitra.social/users/silverpill","id":"https://mitra.social/activities/bite/019e0810-4c45-7ee2-8ef5-5cf0301a39ef","target":"https://marius.federated.id","to":["https://marius.federated.id"],"type":"Bite"}
				req := httptest.NewRequest(
					http.MethodPost,
					"https://marius.federated.id/inbox",
					strings.NewReader(`{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/security/v1","https://w3id.org/security/data-integrity/v2",{"Emoji":"toot:Emoji","Hashtag":"as:Hashtag","sensitive":"as:sensitive","toot":"http://joinmastodon.org/ns#"}],"actor":"https://mitra.social/users/silverpill","id":"https://mitra.social/activities/bite/019e0810-4c45-7ee2-8ef5-5cf0301a39ef","target":"https://marius.federated.id","to":["https://marius.federated.id"],"type":"Bite"}`),
				)
				req.Header.Add("Content-Digest", "sha-256=:Ne3sI5+36+54SZkfRoROfH63nbDK84hEikozFWME4fw=:")
				req.Header.Add("Content-Length", "460")
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "content-digest");keyid="https://mitra.social/users/silverpill#main-key";created=1778251834;alg="rsa-v1_5-sha256"`)
				req.Header.Add("Signature", "sig1=:cwLpgfNFKSF2SZfz5eXTRJLuBOOXuzeEV/wbq7Y9i/NACcP8Uyi2iNiwa1QAbeKYunBG3cVplWvXgCVJYwYI241s6t01iKx7tB6upS8hLANlrbHAkY+c0YKfJaPpaWgWZV44k4DEMP47z5AqZVoRCPqGZUvXWuSbMqAy6CAHNiHp9Tb8mZcpZKFuskP+0Lz972I+rwYGdGCd4UGi7tuJZUY8eW99QIHSiBUqXZs5sSmvzi5JxhlKfXhuob6F7f7fUqfj7iMx/A+4EMi9lf/O+uo/P9fZisXOsX65H/T74vlXCXaascia9c7HHiQdbXhrTuoKB9yhNX1sAel7szdiPw==:")
				return req
			}(),
			sigDuration: 0,
			want:        mitraActorFn,
			wantErr:     nil,
		},
		{
			name:   "tags.pub prod example",
			loader: mldr(emptyActorWithTagsPubKeyFn, s2s.KeyTypePKCS),
			req: func() *http.Request {
				//POST /inbox HTTP/1.1
				//Host: beta.littr.me
				//Accept-Encoding: gzip, br
				//Content-Digest: sha-256=:oQCMcUPL71s97RG1fMMf6qZYPR0E4k6zfwV19iK/Jyc=:
				//Content-Length: 611
				//Content-Type: application/activity+json
				//Date: Fri, 01 May 2026 11:28:22 GMT
				//User-Agent: activitypub.bot/0.45.9 (https://github.com/evanp/activitypub-bot)
				//Signature: sig1=:V2eX+FcO/cePSjdkuUPpgYVpwOmvsbo7S9VWBXnMI698mbIlyScK+BkfVCtndlHcMu5H05agdw69GJOiLEx2iLE7IYouL8hcIiYZFt87vAkt++ohJtAwzLgk7GRX8Ur3pkdEqVtQKZYVyHrfeaQdZEdL8wVeUmBbKXvF1Q6CHaSGvgzkdfoNa8FLleebBMqG9DpJH4ThDx56pOB0vUg6RUdkZuh2XyXWuoLRM+1eLEoBUO3KxBrRcgAxKcXNwsBc5ToEvooGgBwino0Q55QtoTFCJLIUX3MBSvBPe9jRkk8B04a1VIBOu3mgU8hOd0kvZDJvehWxQZxpTGkZ2MBN5w==:
				//Signature-Input: sig1=("@method" "@target-uri" "date" "user-agent" "content-type" "content-digest");keyid="https://tags.pub/user/activitypub/publickey";alg="rsa-v1_5-sha256";created=1777634902
				//
				//{"@context":"https://www.w3.org/ns/activitystreams","id":"https://tags.pub/user/activitypub/announce/cq40liucTUC30vHxTzZz0","type":"Announce","actor":"https://tags.pub/user/activitypub","cc":"https://socialwebfoundation.org/author/evanprodromou/","object":"https://socialwebfoundation.org/?p=144261","published":"2026-05-01T07:52:18.376Z","summary":"activitypub shared \"Social Web Foundation at Wikimedia Hackathon\"","summaryMap":{"en":"activitypub shared \"Social Web Foundation at Wikimedia Hackathon\""},"to":["https://tags.pub/user/activitypub/followers","as:Public"],"updated":"2026-05-01T07:52:18.376Z"}
				req := httptest.NewRequest(
					http.MethodPost,
					"https://beta.littr.me/inbox",
					strings.NewReader(`{"@context":"https://www.w3.org/ns/activitystreams","id":"https://tags.pub/user/activitypub/announce/cq40liucTUC30vHxTzZz0","type":"Announce","actor":"https://tags.pub/user/activitypub","cc":"https://socialwebfoundation.org/author/evanprodromou/","object":"https://socialwebfoundation.org/?p=144261","published":"2026-05-01T07:52:18.376Z","summary":"activitypub shared \"Social Web Foundation at Wikimedia Hackathon\"","summaryMap":{"en":"activitypub shared \"Social Web Foundation at Wikimedia Hackathon\""},"to":["https://tags.pub/user/activitypub/followers","as:Public"],"updated":"2026-05-01T07:52:18.376Z"}`),
				)
				req.Header.Add("Content-Digest", "sha-256=:oQCMcUPL71s97RG1fMMf6qZYPR0E4k6zfwV19iK/Jyc=:")
				req.Header.Add("Content-Length", "611")
				req.Header.Add("Date", "Fri, 01 May 2026 11:28:22 GMT")
				req.Header.Add("Content-Type", "application/activity+json")
				req.Header.Add("User-Agent", "activitypub.bot/0.45.9 (https://github.com/evanp/activitypub-bot)")
				req.Header.Add("Signature-Input", `sig1=("@method" "@target-uri" "date" "user-agent" "content-type" "content-digest");keyid="https://tags.pub/user/activitypub/publickey";alg="rsa-v1_5-sha256";created=1777634902`)
				req.Header.Add("Signature", "sig1=:V2eX+FcO/cePSjdkuUPpgYVpwOmvsbo7S9VWBXnMI698mbIlyScK+BkfVCtndlHcMu5H05agdw69GJOiLEx2iLE7IYouL8hcIiYZFt87vAkt++ohJtAwzLgk7GRX8Ur3pkdEqVtQKZYVyHrfeaQdZEdL8wVeUmBbKXvF1Q6CHaSGvgzkdfoNa8FLleebBMqG9DpJH4ThDx56pOB0vUg6RUdkZuh2XyXWuoLRM+1eLEoBUO3KxBrRcgAxKcXNwsBc5ToEvooGgBwino0Q55QtoTFCJLIUX3MBSvBPe9jRkk8B04a1VIBOu3mgU8hOd0kvZDJvehWxQZxpTGkZ2MBN5w==:")
				return req
			}(),
			sigDuration: 0,
			want:        emptyActorWithTagsPubKeyFn,
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func Test_httpSigVerifier_VerifyRFCSignature_empty_nonce_check(t *testing.T) {
	emptyNonceFn := func() (string, error) { return "", nil }
	sigMaxAgeDuration = enoughForOldTests
	actor := mockRFCActor(prvKeyRSA1, "http://example.com/~jdoe#main")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := httpSigVerifier{loader: mldr(actor, s2s.KeyTypePSS), l: lw.Dev(lw.SetOutput(t.Output()))}
		if _, err := k.VerifyRFCSignature(r); err != nil {
			t.Errorf("VerifyRFCSignature() unexpected error = %v", err)
			return
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	buildReq := func() *http.Request {
		req := mockPostReq([]byte(`{"hello": "world"}`))
		req.URL, _ = url.Parse(srv.URL)
		req.Host = req.URL.Host
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Host", req.Host)
		return req
	}

	signer := s2s.New(s2s.WithActor(&actor, prvKeyRSA1), s2s.WithNonce(emptyNonceFn), s2s.WithAlg(s2s.KeyTypePSS))

	cl := client.New(
		client.WithHTTPClient(srv.Client()),
		client.WithAuthorizationFn(signer.SignRFC9421, signer.SignDraft),
	)

	for i := range 2 {
		t.Run(fmt.Sprintf("iter %d", i), func(t *testing.T) {
			res, err := cl.Do(buildReq())
			if err != nil {
				t.Fatalf("VerifyRFCSignature() round trip unexpected error = %+v", err)
			}
			if res.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(res.Body)
				_ = res.Body.Close()
				t.Errorf("Error response received: %d: %s", res.StatusCode, raw)
			}
		})
	}
}
