package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.sr.ht/~mariusor/lw"
	"github.com/dadrus/httpsig"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/jsonld"
	draft "github.com/go-fed/httpsig"
	"github.com/google/go-cmp/cmp"
)

func TestHTTPSignature(t *testing.T) {
	mockLogger := lw.Dev(lw.SetOutput(t.Output()))
	tests := []struct {
		name    string
		initFns []InitFn
		want    httpSigVerifier
	}{
		{
			name: "empty",
			want: httpSigVerifier{l: lw.Nil()},
		},
		{
			name:    "with logger",
			initFns: []InitFn{WithLogger(mockLogger)},
			want:    httpSigVerifier{l: mockLogger},
		},
		{
			name:    "with storage",
			initFns: []InitFn{WithStorage(st())},
			want:    httpSigVerifier{loader: &localRemoteLoader{st: st()}, l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPSignature(tt.initFns...); !cmp.Equal(got, tt.want, equateKeyLoader) {
				t.Errorf("HTTPSignature() = %s", cmp.Diff(tt.want, got, equateKeyLoader))
			}
		})
	}
}

func areKeyLoader(a, b any) bool {
	_, ok1 := a.(httpSigVerifier)
	_, ok2 := b.(httpSigVerifier)
	return ok1 && ok2
}

func compareKeyLoader(x, y any) bool {
	xe := x.(httpSigVerifier)
	ye := y.(httpSigVerifier)
	//xst, _ := xe.loader.(oauthStore)
	//yst, _ := ye.loader.(oauthStore)
	cx := config{
		//c:  xe.loader.c,
		//st: xst,
		l: xe.l,
	}
	cy := config{
		//c:  ye.loader.c,
		//st: yst,
		l: ye.l,
	}
	return compareConfig(cx, cy)
}

var equateKeyLoader = cmp.FilterValues(areKeyLoader, cmp.Comparer(compareKeyLoader))

func Test_httpSigVerifier_Verify(t *testing.T) {
	type fields struct {
		loader keyLoader
	}
	tests := []struct {
		name        string
		fields      fields
		sigDuration time.Duration
		req         *http.Request
		want        vocab.Actor
		wantErr     error
	}{
		{
			name:    "nil request",
			req:     nil,
			want:    AnonymousActor,
			wantErr: errInvalidStorage,
		},
		{
			name:    "no header",
			fields:  fields{loader: &localRemoteLoader{st: st()}},
			req:     mockGetReq(),
			want:    AnonymousActor,
			wantErr: errors.BadRequestf("unable to initialize HTTP Signatures verifier"),
		}, {
			name: "GET no corresponding signature",
			fields: fields{
				loader: mockLoader{},
			},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`empty=()`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(fmt.Errorf("%w: no signature present for label %s", httpsig.ErrMalformedData, "empty"), "verification failed"),
		},
		{
			name:        "GET rfc9421 - B.2.1. example - wrong private key",
			sigDuration: enoughForOldTests,
			fields: fields{
				loader: mockLoader{it: mockRFCActor(prvKeyRSA1, "test-key-rsa-pss")},
			},
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
			fields: fields{
				loader: ldr(client.New(), nil),
			},
			req: mockGetReq(url.Values{
				"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
				"Signature":       []string{`sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`},
			}),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf("unable to fetch key: test-key-rsa-pss"), "verification failed"),
		},
		{
			name:        "minimal signature using rsa-sha512 example - no content-digest",
			sigDuration: enoughForOldTests,
			fields: fields{
				loader: ldr(client.New(), st(mockRFCActor(prvKeyRSA1, "#main"), mockActorGenKey("http://example.com/~jdoe#main", "http://example.com/~jdoe", prvKeyRSA1))),
			},
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
			fields: fields{
				loader: mldr(mockRFCActor(prvKeyEd25519, "test-key-ed25519")),
			},
			req: rfcMockReq(url.Values{
				"Signature-Input": []string{`sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`},
				"Signature":       []string{`sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`},
			}),
			want: mockRFCActor(prvKeyEd25519, "test-key-ed25519"),
		},
	}
	for _, tt := range tests {
		nonceStore = new(syncedNonceStore)
		if tt.sigDuration > 0 {
			sigMaxAgeDuration = tt.sigDuration
		}
		v := httpSigVerifier{loader: tt.fields.loader, l: lw.Dev(lw.SetOutput(t.Output()))}
		t.Run(tt.name, verifierTest(v, tt.req, tt.want, tt.wantErr))
	}
}

var (
	// Example ECC P-256 Test Key
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-example-ecc-p-256-test-key
	prvECDSA = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`

	pubECDSA = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
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

	// Example Ed25519 Test Key
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-example-ed25519-test-key
	prvEd25519 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`

	pubEd25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
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
		k, err := x509.ParsePKCS8PrivateKey(prvBlockRSA.Bytes)
		if err != nil {
			panic(err)
		}
		return k.(*rsa.PrivateKey)
	}()
	pubKeyRSA = func() *rsa.PublicKey {
		pubBlockRSA, _ := pem.Decode([]byte(pubRSA))
		k, _ := x509.ParsePKIXPublicKey(pubBlockRSA.Bytes)
		return k.(*rsa.PublicKey)
	}()

	// NOTE(marius): values from the Example RSA key test cases in the HTTP Signatures RFC9421
	// https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.1
	prvRSA1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`

	pubRSA1 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----
`

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

func Test_compatibleDraftVerifyAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		pubKey crypto.PublicKey
		want   []draft.Algorithm
	}{
		{
			name:   "empty",
			pubKey: vocab.PublicKey{},
		},
		{
			name:   "rsa x509",
			pubKey: pubKeyRSA,
			want:   []draft.Algorithm{draft.RSA_SHA256},
		},
		{
			name:   "rsa pkcs#1",
			pubKey: pubKeyRSA1,
			want:   []draft.Algorithm{draft.RSA_SHA256},
		},
		{
			name:   "ecdsa",
			pubKey: pubKeyECDSA,
			want:   []draft.Algorithm{draft.ECDSA_SHA256},
		},
		{
			name:   "ed25519",
			pubKey: pubKeyEd25519,
			want:   []draft.Algorithm{draft.ED25519},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compatibleDraftVerifyAlgorithms(tt.pubKey); !cmp.Equal(got, tt.want) {
				t.Errorf("compatibleVerifyAlgorithms() = %s", cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestLoadRemoteKey(t *testing.T) {
	type args struct {
		ctx context.Context
		c   ActivityPubClient
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
			wantErr: errInvalidClient,
		},
		{
			name: "empty key IRI",
			args: args{},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			want:    AnonymousActor,
			wantErr: errEmptyIRI,
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
			wantErr: errors.Newf("unable to fetch key: http://example.com/~jdoe#main"),
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
			wantErr: errors.Annotatef(errors.Newf("unexpected end of JSON input"), "unable to decode key or actor: http://example.com/~jdoe/key"),
		},
		{
			name: "good key, bad actor",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe/key",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor()
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
			wantErr: errors.Newf("unable to fetch actor: http://example.com/~jdoe/key"),
		},
		{
			name: "good key, good actor",
			args: args{
				ctx: context.Background(),
				iri: "http://example.com/~jdoe/key",
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) {
				actor := mockActor()
				payload, _ := vocab.MarshalJSON(actor)
				if strings.HasSuffix(r.URL.Path, "/key") {
					actor.PublicKey.ID = "http://example.com/~jdoe/key"
					payload, _ = jsonld.Marshal(actor.PublicKey)
				}
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			},
			want: mockActor(),
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
				actor := mockActor()
				payload, _ := vocab.MarshalJSON(actor)
				w.Header().Set("Cache-Control", "public")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(payload)
			},
			want: mockActor(),
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

var (
	// NOTE(marius): these values come from the Appendix C of Draft 12 for the HTTP Signatures RFC
	// https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#appendix-C
	cavageRSAPubKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

	cavageRSAPrvKey = `-----BEGIN RSA PRIVATE KEY-----
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

	cavagePrvKeyRSA = func() *rsa.PrivateKey {
		prvBlockRSA, _ := pem.Decode([]byte(cavageRSAPrvKey))
		k, _ := x509.ParsePKCS1PrivateKey(prvBlockRSA.Bytes)
		return k
	}()

	cavageActor = func() vocab.Actor {
		act := mockActor()
		act.PublicKey.ID = "Test"
		act.PublicKey.PublicKeyPem = cavageRSAPubKey
		return act
	}()
)

func mockPostReq(body []byte, hh ...url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewReader(body))
	for _, h := range hh {
		for k, v := range h {
			r.Header[k] = v
		}
	}
	r.Header.Add("Content-Length", strconv.Itoa(len(body)))
	return r
}

// NOTE(marius): these values also come from the Appendix C of Draft 12 for the HTTP Signatures RFC
// https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#appendix-C:~:text=All%20examples%20use%20this%20request
func cavageMockReq(hh ...url.Values) *http.Request {
	cavageHdrs := url.Values{
		"Date":         []string{"Sun, 05 Jan 2014 21:31:40 GMT"},
		"Content-Type": []string{"application/json"},
		"Digest":       []string{"SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
	}
	for _, h := range hh {
		for k, v := range h {
			cavageHdrs[k] = v
		}
	}
	return mockPostReq([]byte(`{"hello": "world"}`), cavageHdrs)
}

func Test_httpSigVerifier_VerifyDraftSignature(t *testing.T) {
	testActor := mockActor()
	testActor.ID = "Test"
	testActor.PublicKey.ID = "Test"
	type fields struct {
		loader keyLoader
	}
	tests := []struct {
		name    string
		fields  fields
		created time.Time
		req     *http.Request
		want    vocab.Actor
		wantErr error
	}{
		{
			name:    "empty",
			fields:  fields{},
			req:     nil,
			want:    AnonymousActor,
			wantErr: errInvalidRequest,
		},
		{
			name:    "no loader",
			fields:  fields{},
			req:     mockGetReq(),
			want:    AnonymousActor,
			wantErr: errInvalidClient,
		},
		{
			name:    "no headers",
			fields:  fields{loader: mockLoader{}},
			req:     mockGetReq(),
			want:    AnonymousActor,
			wantErr: errors.Annotatef(errors.Newf(`neither "Signature" nor "Authorization" have signature parameters`), "unable to initialize HTTP Signatures verifier"),
		},
		{
			name:    "bad signature",
			fields:  fields{loader: mockLoader{}},
			req:     mockGetReq(url.Values{"Signature": []string{"bad"}}),
			want:    AnonymousActor,
			wantErr: errors.NewBadRequest(errors.NotFoundf("neither \"Signature\" nor \"Authorization\" have signature parameters"), "unable to initialize HTTP Signatures verifier"),
		},
		{
			name: "good signature",
			fields: fields{
				loader: localRemoteLoader{
					st: st(cavageActor, mockActorKey("http://example.com/~jdoe#main", "http://example.com/~jdoe", cavagePrvKeyRSA), cavagePrvKeyRSA),
				},
			},
			req: cavageMockReq(url.Values{
				"Signature": []string{`keyId="http://example.com/~jdoe#main",algorithm="rsa-sha512",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="`},
				"Date":      []string{`Sun, 05 Jan 2014 21:31:40 GMT`},
			}),
			want: mockActor(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := httpSigVerifier{
				loader: tt.fields.loader,
				l:      lw.Dev(lw.SetOutput(t.Output())),
			}
			got, err := k.VerifyDraftSignature(tt.req)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Fatalf("VerifyDraftSignature() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("VerifyDraftSignature() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}
