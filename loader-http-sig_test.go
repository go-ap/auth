package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	"github.com/go-fed/httpsig"
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
		iriIsLocal func(vocab.IRI) bool
		ignore     vocab.IRIs
		c          *client.C
		st         oauthStore
		l          lw.Logger
	}
	tests := []struct {
		name      string
		fields    fields
		arg       vocab.IRI
		handlerFn http.HandlerFunc
		want      vocab.Actor
		wantKey   *vocab.PublicKey
		wantErr   error
	}{
		{
			name:    "empty",
			fields:  fields{},
			want:    AnonymousActor,
			wantKey: (*vocab.PublicKey)(nil),
			wantErr: errInvalidClient,
		},
		{
			name: "not found",
			fields: fields{
				iriIsLocal: isNotLocal,
				c:          client.New(),
				l:          lw.Dev(lw.SetOutput(t.Output())),
				st:         st(),
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			arg:     vocab.IRI("http://example.com/~jdoe#main"),
			want:    AnonymousActor,
			wantKey: nil,
			wantErr: errors.NotFoundf("unable to fetch actor"),
		},
		{
			name: "local found actor",
			fields: fields{
				iriIsLocal: isNotLocal,
				c:          client.New(),
				l:          lw.Dev(lw.SetOutput(t.Output())),
				st:         st(actorKeyMock(pubRSA), mockActor("http://example.com")),
			},
			arg:  vocab.IRI("http://example.com/~jdoe#main"),
			want: mockActor("http://example.com"),
			wantKey: func() *vocab.PublicKey {
				k := mockActor("http://example.com").PublicKey
				return &k
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.handlerFn != nil {
				srv := httptest.NewServer(tt.handlerFn)
				tt.fields.c = client.New(client.WithHTTPClient(srv.Client()))
			}
			a := keyLoader{
				ignore: tt.fields.ignore,
				c:      tt.fields.c,
				st:     tt.fields.st,
				l:      lw.Dev(lw.SetOutput(t.Output())),
			}
			act, key, err := a.LoadActorFromKeyIRI(tt.arg)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("LoadActorFromKeyIRI() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(act, tt.want, EquateItems) {
				t.Errorf("LoadActorFromKeyIRI() got actor = %s", cmp.Diff(tt.want, act, EquateItems))
			}
			if !cmp.Equal(key, tt.wantKey) {
				t.Errorf("LoadActorFromKeyIRI() got key = %s", cmp.Diff(tt.wantKey, key))
			}
		})
	}
}

func Test_keyLoader_GetKey(t *testing.T) {
	type result struct {
		act vocab.Actor
		key crypto.PublicKey
	}
	type fields struct {
		baseURL    string
		iriIsLocal func(vocab.IRI) bool
		ignore     vocab.IRIs
		st         oauthStore
	}
	tests := []struct {
		name      string
		fields    fields
		arg       string
		handlerFn http.HandlerFunc
		want      result
		wantErr   error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("empty IRI"),
		},
		{
			name: "ignored url",
			fields: fields{
				ignore: vocab.IRIs{"http://example.com/~jdoe"},
			},
			arg:     "http://example.com/~jdoe",
			wantErr: errors.Forbiddenf("actor is blocked"),
		},
		{
			name: "ignored host",
			fields: fields{
				ignore: vocab.IRIs{"http://example.com"},
			},
			arg:     "http://example.com/~jdoe",
			wantErr: errors.Forbiddenf("actor is blocked"),
		},
		{
			name: "remote key IRI as separate resource",
			arg:  "http://example.com/~jdoe/key",
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor("http://" + r.Host)
				actor.PublicKey.ID = vocab.IRI("http://" + r.Host + "/~jdoe/key")

				payload, _ := vocab.MarshalJSON(actor)
				if strings.HasSuffix(r.URL.Path, "/key") {
					payload, _ = jsonld.Marshal(actor.PublicKey)
				}

				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			}),
			want: result{
				act: vocab.Actor{
					ID:   vocab.IRI("http://example.com/~jdoe"),
					Type: vocab.PersonType,
					PublicKey: vocab.PublicKey{
						ID:           vocab.IRI("http://example.com/~jdoe/key"),
						Owner:        vocab.IRI("http://example.com/~jdoe"),
						PublicKeyPem: pemEncodePublicKey(prv),
					},
				},
				key: prv.Public(),
			},
		},
		{
			name: "remote key IRI as actor resource",
			arg:  "http://example.com/~jdoe#main",
			want: result{
				act: mockActor("http://example.com"),
				key: prv.Public(),
			},
			handlerFn: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := http.StatusOK
				actor := mockActor("http://example.com")
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
			if tt.fields.st == nil {
				tt.fields.st = st()
			}
			k := &keyLoader{
				c:      client.New(client.WithHTTPClient(srv.Client())),
				l:      lw.Dev(lw.SetOutput(t.Output())),
				st:     tt.fields.st,
				ignore: tt.fields.ignore,
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
			wantErr: errors.BadRequestf("unable to initialize HTTP Signatures verifier"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, verifierTest(tt.a, tt.r, tt.want, tt.wantErr))
	}
}

var (
	prvECDSA = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDDHJkGMt3IYM81fjrMGyySIWs2XixetQ9eVzXO0aPt1rMz2DvMhNGe
ngeqMW2cXACgBwYFK4EEACKhZANiAASNoNI4Gy6L7QRDqlJdBsXRnhRGmPCMUmxT
xUSWByh4ybAXq9FTis4C1QMf7rOlXdf623uVi5m+rR1Uk8nHDeVQ24i4aypjdGAP
Bwxj6JoQCBRMzXABnT3sENgDuyXKo/s=
-----END EC PRIVATE KEY-----`

	pubECDSA = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEjaDSOBsui+0EQ6pSXQbF0Z4URpjwjFJs
U8VElgcoeMmwF6vRU4rOAtUDH+6zpV3X+tt7lYuZvq0dVJPJxw3lUNuIuGsqY3Rg
DwcMY+iaEAgUTM1wAZ097BDYA7slyqP7
-----END PUBLIC KEY-----`

	prvKeyECDSA = func() *ecdsa.PrivateKey {
		prvBlockECDSA, _ := pem.Decode([]byte(prvECDSA))
		k, _ := x509.ParseECPrivateKey(prvBlockECDSA.Bytes)
		return k
	}()
	pubKeyECDSA = func() *ecdsa.PublicKey {
		pubBlock, _ := pem.Decode([]byte(pubECDSA))
		k, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		return k.(*ecdsa.PublicKey)
	}()

	prvEd25519 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIBtETC3LLbPMz5bZx7T5HruR1A4B/QOr8ZIC8NK1voC
-----END PRIVATE KEY-----`

	pubEd25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApd3C+e/M4YmvRvlYD/3nUvq4z5cJTyc5zMxPSPZha8M=
-----END PUBLIC KEY-----`

	prvKeyEd25519 = func() ed25519.PrivateKey {
		prvBlockEd25519, _ := pem.Decode([]byte(prvEd25519))
		k, _ := x509.ParsePKCS8PrivateKey(prvBlockEd25519.Bytes)
		return k.(ed25519.PrivateKey)
	}()
	pubKeyEd25519 = func() ed25519.PublicKey {
		pubBlock, _ := pem.Decode([]byte(pubEd25519))
		k, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		return k.(ed25519.PublicKey)
	}()

	prvRSA = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEZNd5f+5jjw7Y
vzhwniZgFOiz80cOWAJtMGtmorjkjaQPE2cmrgWvEHiCYqQ0jnbCSJrMPZXUlXUm
vsdHaczpbHKlnPKUgC35QpXs3NikWvoZFBhJR99lbGuZilsQj/lMi7Ht7lzmZRDR
/ZeapRi+otxjSKNe3FH1ONIaXZdBEfRHKfRW2FV9W3L76gX9jsH/2s26r6LYlyLM
lnQkt2dM+GwYSG4pv/Kl/KE2i/UdJ/o/tealiO5usyZwK3U2vZCJaseMWDbluHTM
Q1RPPV8SeI5pBqREa2XrSwbcZUI+TaB+xiPvIAjrTboxLY5XyIDwjag+a/aMvzRx
JAKRmRqhAgMBAAECggEAGYiEzSqZSz9Xrk1aIKYnFhnR0UeBRvehRSHk7MCeKjTS
DhW3NPuuCH8rM8RwVdbp0MOQwJoHJ07RHtrx3LKALh7n3ulDTpRFpeEGzfc+gUvE
tUr8B1b9T9njOWCYC1S0lEObO/RgBqJAKBUAx13MlEhnP887UkNxsmCTTFM7rX1W
AVgHGZo71M6IebHjoLEFmYAXtFgY3+W29J3JOAUsWWCIZYntnOtNAslRYjzyuTRh
bDTKayKMuRuPo4/jgQhsHS6qsRonK0dQRKLuBX8iHyoXFQP7GVea9liHnm9lqwQ1
Ve4zvD4IUbV71NVZ6xsY3Nfr7/f8ehatMhSZ/H6BKwKBgQD3Eq7yhOmzGk8Woa2b
7NBB9UwCoGHIWh/lXj731a/3zD85sS7VXdvyXOwhilMpx/lNmTBhq2ko5qf122xu
JyQ1DfsKvHs0sHqL1ZVHovpe0lvwxu1Nj/HfsEqlt//qFvXa4Gp5uw/hqcLcxfSa
Yo8z6m/+QPESMPxwD3FaUmKuiwKBgQDLfWYv/t6m+4v0ROSY+oGW/r6HbYkFWodw
UU+S2THwOttddJDEOznEZxmJhqAXPMChTkmXL8kn1aRSmn/AHJDVywCxv0xNiIcR
kjfFmmzdig/HcBoWHPc5aAoZorxDEIb6NWEJt/vEDfnOOLItfufKCy9aKdQ7pwjP
FcPH7TwNAwKBgFTPNP5KYW35Oeyq0s0THOmHKfA83VPIm+o/z52C3ERS9+D10P2s
mjM3claRBLryycC5NMJR9Gb1xfG+wBmPlf4gLmwhBqmvamFVj0hnyUmDK8wafJqD
LqN6ACWiY1YXS402O1ZNv8XWX+0ohi34Zu+LKaY85IM6DWzp4B8A6J7BAoGBALkK
SAE/B6LavXKbrzA5I9x1vDYUcfQPVXfaSLzlipbEPrRmCjqXDLm/cyZu6GcZFKXa
NesoRghWKv3+hkrg7weqePApX65lh0WAK/0hpvtxz1VxaBdRsbJfHEghhoaJoeQm
5B3dUzD98HoJbmUWsJo2v5GC1f6Erur5BLZp0SCXAoGAPFS3336Z1pK0Ne+Qw83x
V9dcGszH2HYfU4AVOyxIRK6DDsw0k/r4zi/0AfRjnPlP89qffTZfkEgW+/jXQYzr
B5MKfJ21HzAim4dyNzhbViNqzQtRZhP7/ESJJVF1CUbyIr3xqwww0rVdWxgTPrra
CymanYHXIAFVDKU/1A099Uw=
-----END PRIVATE KEY-----`

	pubRSA = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGTXeX/uY48O2L84cJ4m
YBTos/NHDlgCbTBrZqK45I2kDxNnJq4FrxB4gmKkNI52wkiazD2V1JV1Jr7HR2nM
6WxypZzylIAt+UKV7NzYpFr6GRQYSUffZWxrmYpbEI/5TIux7e5c5mUQ0f2XmqUY
vqLcY0ijXtxR9TjSGl2XQRH0Ryn0VthVfVty++oF/Y7B/9rNuq+i2JcizJZ0JLdn
TPhsGEhuKb/ypfyhNov1HSf6P7XmpYjubrMmcCt1Nr2QiWrHjFg25bh0zENUTz1f
EniOaQakRGtl60sG3GVCPk2gfsYj7yAI6026MS2OV8iA8I2oPmv2jL80cSQCkZka
oQIDAQAB
-----END PUBLIC KEY-----`

	prvKeyRSA = func() *rsa.PrivateKey {
		prvBlockRSA, _ := pem.Decode([]byte(prvRSA))
		k, _ := x509.ParsePKCS8PrivateKey(prvBlockRSA.Bytes)
		return k.(*rsa.PrivateKey)
	}()
	pubKeyRSA = func() *rsa.PublicKey {
		pubBlockRSA, _ := pem.Decode([]byte(pubRSA))
		k, _ := x509.ParsePKIXPublicKey(pubBlockRSA.Bytes)
		return k.(*rsa.PublicKey)
	}()

	prvRSA1 = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`

	// NOTE(marius): PKCS1 encoded public key
	pubRSA1 = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMIUQ0bDffIaKHL3akONlCGXQLfqs8mP4K99ILz6rbyHEDXrVAU1R3Xf
C4JNRyrRB3aqwF7/aEXJzYMIkmDSHUvvz7pnhQxHsQ5yl91QT0d/eb+Gz4VRHjm4
El4MrUdIUcPxscoPqS/wU8Z8lOi1z7bGMnChiL7WGqnV8h6RrGzJAgMBAAE=
-----END RSA PUBLIC KEY-----`

	prvKeyRSA1 = func() *rsa.PrivateKey {
		prvBlockRSA, _ := pem.Decode([]byte(prvRSA1))
		k, _ := x509.ParsePKCS1PrivateKey(prvBlockRSA.Bytes)
		return k
	}()

	pubKeyRSA1 = func() *rsa.PublicKey {
		pubBlockRSA, _ := pem.Decode([]byte(pubRSA1))
		k, _ := x509.ParsePKCS1PublicKey(pubBlockRSA.Bytes)
		return k
	}()
)

func actorKeyMock(pem string) vocab.PublicKey {
	return vocab.PublicKey{
		ID:           "https://example.com/~johndoe#main",
		Owner:        "https://example.com/~johndoe",
		PublicKeyPem: pem,
	}
}

func Test_toCryptoPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		key     vocab.PublicKey
		want    crypto.PublicKey
		wantErr error
	}{
		{
			name:    "empty",
			key:     vocab.PublicKey{},
			wantErr: errors.Newf("unable to decode PEM payload for public key"),
		},
		{
			name: "rsa x509",
			key:  actorKeyMock(pubRSA),
			want: prvKeyRSA.Public(),
		},
		{
			name: "rsa pkcs#1",
			key:  actorKeyMock(pubRSA1),
			want: prvKeyRSA1.Public(),
		},
		{
			name: "ecdsa",
			key:  actorKeyMock(pubECDSA),
			want: prvKeyECDSA.Public(),
		},
		{
			name: "ed25519",
			key:  actorKeyMock(pubEd25519),
			want: prvKeyEd25519.Public(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toCryptoPublicKey(tt.key)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("toCryptoPublicKey() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquatePublicKeys) {
				t.Errorf("toCryptoPublicKey() got = %s", cmp.Diff(tt.want, got, EquatePublicKeys))
			}
		})
	}
}

func arePubKeys(a, b any) bool {
	_, ok1 := a.(cryptoPubKey)
	_, ok2 := b.(cryptoPubKey)
	return ok1 && ok2
}

type cryptoPubKey interface {
	Equal(key crypto.PublicKey) bool
}

func comparePubKeys(x, y any) bool {
	if rcmp, ok := x.(cryptoPubKey); ok {
		return rcmp.Equal(y)
	}
	return false
}

var EquatePublicKeys = cmp.FilterValues(arePubKeys, cmp.Comparer(comparePubKeys))

func Test_keyLoader_iriIsIgnored(t *testing.T) {
	tests := []struct {
		name string
		k    keyLoader
		iri  vocab.IRI
		want bool
	}{
		{
			name: "empty",
			k:    keyLoader{},
			want: false,
		},
		{
			name: "nil ignored",
			k:    keyLoader{},
			iri:  "http://example.com",
			want: false,
		},
		{
			name: "empty ignored",
			k: keyLoader{
				ignore: []vocab.IRI{},
			},
			iri:  "http://example.com",
			want: false,
		},
		{
			name: "is ignored",
			k: keyLoader{
				ignore: []vocab.IRI{"http://example.com"},
			},
			iri:  "http://example.com",
			want: true,
		},
		{
			name: "is substring ignored",
			k: keyLoader{
				ignore: []vocab.IRI{"http://example.com"},
			},
			iri:  "http://example.com/~jdoe",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.k.iriIsIgnored(tt.iri); got != tt.want {
				t.Errorf("iriIsIgnored() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_compatibleVerifyAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		pubKey crypto.PublicKey
		want   []httpsig.Algorithm
	}{
		{
			name:   "empty",
			pubKey: vocab.PublicKey{},
		},
		{
			name:   "rsa x509",
			pubKey: pubKeyRSA,
			want:   []httpsig.Algorithm{httpsig.RSA_SHA256, httpsig.RSA_SHA512},
		},
		{
			name:   "rsa pkcs#1",
			pubKey: pubKeyRSA1,
			want:   []httpsig.Algorithm{httpsig.RSA_SHA256, httpsig.RSA_SHA512},
		},
		{
			name:   "ecdsa",
			pubKey: pubKeyECDSA,
			want:   []httpsig.Algorithm{httpsig.ECDSA_SHA512, httpsig.ECDSA_SHA256},
		},
		{
			name:   "ed25519",
			pubKey: pubKeyEd25519,
			want:   []httpsig.Algorithm{httpsig.ED25519},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compatibleVerifyAlgorithms(tt.pubKey); !cmp.Equal(got, tt.want) {
				t.Errorf("compatibleVerifyAlgorithms() = %s", cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestLoadRemoteKey(t *testing.T) {
	type args struct {
		ctx context.Context
		c   *client.C
		iri vocab.IRI
	}
	tests := []struct {
		name      string
		handlerFn http.HandlerFunc
		args      args
		want      vocab.Actor
		wantKey   *vocab.PublicKey
		wantErr   error
	}{
		{
			name:    "empty",
			args:    args{},
			want:    AnonymousActor,
			wantErr: errors.Newf("nil http client"),
		},
		{
			name: "empty key IRI",
			args: args{},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf(`Get "": unsupported protocol scheme ""`), "unable to fetch key"),
		},
		{
			name: "not found",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe#main",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			want:    AnonymousActor,
			wantErr: errors.Newf("unable to fetch key"),
		},
		{
			name: "bad key json",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe/key",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(``))
				return
			},
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf("unexpected end of JSON input"), "unable to decode key or actor"),
		},
		{
			name: "good key, bad actor",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe/key",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor("http://example.com")
				if strings.HasSuffix(r.URL.Path, "/key") {
					actor.PublicKey.ID = "http://example.com/~jdoe/key"
					payload, _ := jsonld.Marshal(actor.PublicKey)

					w.Header().Set("Cache-Control", "public")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(payload)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			want: AnonymousActor,
			wantKey: func() *vocab.PublicKey {
				p := mockActorKey("http://example.com/~jdoe/key", "http://example.com/~jdoe", prv)
				return &p
			}(),
			wantErr: errors.Newf("unable to fetch actor"),
		},
		{
			name: "good key, good actor",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe/key",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor("http://example.com")
				payload, _ := vocab.MarshalJSON(actor)
				if strings.HasSuffix(r.URL.Path, "/key") {
					actor.PublicKey.ID = "http://example.com/~jdoe/key"
					payload, _ = jsonld.Marshal(actor.PublicKey)
				}
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			},
			want: mockActor("http://example.com"),
			wantKey: func() *vocab.PublicKey {
				p := mockActorKey("http://example.com/~jdoe/key", "http://example.com/~jdoe", prv)
				return &p
			}(),
		},
		{
			name: "good actor",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe#main",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor("http://example.com")
				payload, _ := vocab.MarshalJSON(actor)
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			},
			want: mockActor("http://example.com"),
			wantKey: func() *vocab.PublicKey {
				p := mockActorKey("http://example.com/~jdoe#main", "http://example.com/~jdoe", prv)
				return &p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.handlerFn != nil {
				srv := httptest.NewServer(tt.handlerFn)
				tt.args.c = client.New(client.WithHTTPClient(srv.Client()))
			}
			act, pub, err := LoadRemoteKey(tt.args.ctx, tt.args.c, tt.args.iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("LoadRemoteKey() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(act, tt.want, EquateItems) {
				t.Errorf("LoadRemoteKey() got = %s", cmp.Diff(tt.want, act, EquateItems))
			}
			if !cmp.Equal(pub, tt.wantKey, EquatePublicKeys) {
				t.Errorf("LoadRemoteKey() got1 = %s", cmp.Diff(tt.wantKey, pub, EquatePublicKeys))
			}
		})
	}
}
