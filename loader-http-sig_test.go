package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

	prvEd25519 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIENuo6tAn+SGsIM2z6bVx7VZpy4HYCeXKl1hV6uT4DVb
-----END PRIVATE KEY-----`

	pubEd25519 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEjaDSOBsui+0EQ6pSXQbF0Z4URpjwjFJs
U8VElgcoeMmwF6vRU4rOAtUDH+6zpV3X+tt7lYuZvq0dVJPJxw3lUNuIuGsqY3Rg
DwcMY+iaEAgUTM1wAZ097BDYA7slyqP7
-----END PUBLIC KEY-----`

	prvKeyEd25519 = func() ed25519.PrivateKey {
		prvBlockEd25519, _ := pem.Decode([]byte(prvEd25519))
		k, _ := x509.ParsePKCS8PrivateKey(prvBlockEd25519.Bytes)
		return k.(ed25519.PrivateKey)
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
)

func ActorKey(pem string) vocab.PublicKey {
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
			name: "rsa",
			key:  ActorKey(pubRSA),
			want: prvKeyRSA.Public(),
		},
		{
			name: "ecdsa",
			key:  ActorKey(pubECDSA),
			want: prvKeyECDSA.Public(),
		},
		//{
		//	// NOTE(marius): this returns a ECDSA public key for some reason.
		//	name: "ed25519",
		//	key:  ActorKey(pubEd25519),
		//	want: prvKeyEd25519.Public(),
		//},
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
