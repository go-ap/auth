package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openshift/osin"
)

var (
	ignoreIRIs     = vocab.IRIs{"http://example.com", "http://example.com/~djoe"}
	mockLocalIRIFn = func(_ vocab.IRI) bool { return false }
)

func TestConfig(t *testing.T) {
	mockLogger := lw.Dev(lw.SetOutput(t.Output()))
	type args struct {
		cl      *client.C
		initFns []InitFn
	}
	tests := []struct {
		name string
		args args
		want config
	}{
		{
			name: "empty",
			args: args{},
			want: config{l: lw.Nil()},
		},
		{
			name: "with logger",
			args: args{cl: nil, initFns: []InitFn{WithLogger(mockLogger)}},
			want: config{l: mockLogger},
		},
		{
			name: "with ignoreIRIs",
			args: args{cl: nil, initFns: []InitFn{WithIgnoreList(ignoreIRIs...)}},
			want: config{ignore: ignoreIRIs, l: lw.Nil()},
		},
		{
			name: "with local IRI func",
			args: args{cl: nil, initFns: []InitFn{WithLocalIRIFn(mockLocalIRIFn)}},
			want: config{iriIsLocal: mockLocalIRIFn, l: lw.Nil()},
		},
		{
			name: "with storage",
			args: args{cl: nil, initFns: []InitFn{WithStorage(st())}},
			want: config{st: st(), l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Config(tt.args.cl, tt.args.initFns...); !cmp.Equal(got, tt.want, equateConfig) {
				t.Errorf("Config() = %s", cmp.Diff(tt.want, got, equateConfig))
			}
		})
	}
}

func areConfig(a, b any) bool {
	_, ok1 := a.(config)
	_, ok2 := b.(config)
	return ok1 && ok2
}

func compareConfig(x, y any) bool {
	xe := x.(config)
	ye := y.(config)
	if !cmp.Equal(xe.c, ye.c, cmpopts.IgnoreUnexported(http.Client{})) {
		return false
	}
	if !cmp.Equal(xe.iriIsLocal, ye.iriIsLocal, equateFuncs) {
		return false
	}
	if !reflect.ValueOf(xe.l).Equal(reflect.ValueOf(ye.l)) {
		return false
	}
	if !slices.Equal(xe.ignore, ye.ignore) {
		return false
	}
	if xe.st == nil || ye.st == nil {
		return xe.st == ye.st
	}
	return true
}

var equateConfig = cmp.FilterValues(areConfig, cmp.Comparer(compareConfig))

func areFuncs(a, b any) bool {
	ta := reflect.TypeOf(a)
	tb := reflect.TypeOf(b)
	return ta != nil && ta.Kind() == reflect.Func && tb != nil && tb.Kind() == reflect.Func
}

func compareFuncs(x, y any) bool {
	px := *(*unsafe.Pointer)(unsafe.Pointer(&x))
	py := *(*unsafe.Pointer)(unsafe.Pointer(&y))
	return px == py
}

var equateFuncs = cmp.FilterValues(areFuncs, cmp.Comparer(compareFuncs))

func st(el ...any) mockStore {
	s := mockStore{}
	for _, in := range el {
		if it, ok := in.(vocab.Item); ok {
			s.it = it
		}
		if ac, ok := in.(osin.AccessData); ok {
			s.ac = ac
		}
	}
	return s
}

type mockStore struct {
	it vocab.Item
	ac osin.AccessData
}

func (ms mockStore) Load(iri vocab.IRI, _ ...filters.Check) (vocab.Item, error) {
	if vocab.IsNil(ms.it) || !ms.it.GetLink().Equal(iri) {
		return nil, errors.NotFoundf("not found")
	}
	return ms.it, nil
}

func (ms mockStore) LoadAccess(tok string) (*osin.AccessData, error) {
	if ms.ac.AccessToken == tok {
		return nil, errors.NotFoundf("not found")
	}
	return &ms.ac, nil
}

func TestResolver(t *testing.T) {
	mockLogger := lw.Dev(lw.SetOutput(t.Output()))
	type args struct {
		cl      *client.C
		initFns []InitFn
	}
	tests := []struct {
		name string
		args args
		want actorResolver
	}{
		{
			name: "empty",
			args: args{},
			want: actorResolver{l: lw.Nil()},
		},
		{
			name: "with logger",
			args: args{cl: nil, initFns: []InitFn{WithLogger(mockLogger)}},
			want: actorResolver{l: mockLogger},
		},
		{
			name: "with ignoreIRIs",
			args: args{cl: nil, initFns: []InitFn{WithIgnoreList(ignoreIRIs...)}},
			want: actorResolver{ignore: ignoreIRIs, l: lw.Nil()},
		},
		{
			name: "with local IRI func",
			args: args{cl: nil, initFns: []InitFn{WithLocalIRIFn(mockLocalIRIFn)}},
			want: actorResolver{iriIsLocal: mockLocalIRIFn, l: lw.Nil()},
		},
		{
			name: "with storage",
			args: args{cl: nil, initFns: []InitFn{WithStorage(st())}},
			want: actorResolver{st: st(), l: lw.Nil()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolver(tt.args.cl, tt.args.initFns...); !cmp.Equal(got, tt.want, equateResolver) {
				t.Errorf("Resolver() = %s", cmp.Diff(tt.want, got, equateResolver))
			}
		})
	}
}

func areResolver(a, b any) bool {
	_, ok1 := a.(actorResolver)
	_, ok2 := b.(actorResolver)
	return ok1 && ok2
}

func compareResolver(x, y any) bool {
	xe := x.(actorResolver)
	ye := y.(actorResolver)
	return compareConfig(config(xe), config(ye))
}

var equateResolver = cmp.FilterValues(areResolver, cmp.Comparer(compareResolver))

func mockReq(hh ...url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	for _, h := range hh {
		for k, v := range h {
			r.Header[k] = v
		}
	}
	return r
}

func Test_actorResolver_Verify(t *testing.T) {
	tests := []struct {
		name    string
		a       actorResolver
		r       *http.Request
		want    vocab.Actor
		wantErr error
	}{
		{
			name:    "nil request",
			a:       actorResolver{l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       nil,
			want:    AnonymousActor,
			wantErr: errInvalidStorage,
		},
		{
			name:    "no header",
			a:       actorResolver{st: st(), l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       mockReq(),
			want:    AnonymousActor,
			wantErr: nil,
		},
		{
			name: "failed bearer",
			a: actorResolver{
				st: st(),
				l:  lw.Dev(lw.SetOutput(t.Output())),
			},
			r:       mockReq(url.Values{"Authorization": []string{"Bearer -invalid-"}}),
			want:    AnonymousActor,
			wantErr: errors.NotFoundf("not found"),
		},
		{
			name: "success",
			a: actorResolver{
				st: st(mockActor("http://example.com"), mockAccess("test", defaultClient)),
				l:  lw.Dev(lw.SetOutput(t.Output())),
			},
			r:    mockReq(url.Values{"Authorization": []string{"Bearer -invalid-"}}),
			want: mockActor("http://example.com"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, verifierTest(tt.a, tt.r, tt.want, tt.wantErr))
	}
}

var defaultClient = &osin.DefaultClient{
	Id:          "test-client",
	Secret:      "asd",
	RedirectUri: "http://example.com",
	UserData:    nil,
}

func mockAuth(code string, cl osin.Client) *osin.AuthorizeData {
	return &osin.AuthorizeData{
		Client:    cl,
		Code:      code,
		ExpiresIn: 10,
		CreatedAt: time.Now().Add(10 * time.Minute).Round(10 * time.Minute),
		UserData:  vocab.IRI("http://example.com/~jdoe"),
	}
}

func mockAccess(code string, cl osin.Client) osin.AccessData {
	ad := osin.AccessData{
		Client:        cl,
		AuthorizeData: mockAuth("test-code", cl),
		AccessToken:   code,
		ExpiresIn:     10,
		Scope:         "none",
		RedirectUri:   "http://localhost",
		CreatedAt:     time.Now().Add(10 * time.Minute).Round(10 * time.Minute),
		UserData:      vocab.IRI("http://example.com/~jdoe"),
	}
	if code != "refresh-666" {
		ad.RefreshToken = "refresh-666"
		ad.AccessData = &osin.AccessData{
			Client:        cl,
			AuthorizeData: mockAuth("test-code", cl),
			AccessToken:   "refresh-666",
			ExpiresIn:     10,
			Scope:         "none",
			RedirectUri:   "http://localhost",
			CreatedAt:     time.Now().Add(10 * time.Minute).Round(10 * time.Minute),
			UserData:      vocab.IRI("http://example.com/~jdoe"),
		}
	}
	return ad
}

type verifier interface {
	Verify(*http.Request) (vocab.Actor, error)
}

func verifierTest(a verifier, r *http.Request, wantItem vocab.Item, wantErr error) func(*testing.T) {
	return func(t *testing.T) {
		got, err := a.Verify(r)
		if !cmp.Equal(err, wantErr, EquateWeakErrors) {
			t.Errorf("%T.Verify() error = %s", a, cmp.Diff(wantErr, err, EquateWeakErrors))
			return
		}
		if !cmp.Equal(got, wantItem, EquateItems) {
			t.Errorf("%T.Verify() got = %s", a, cmp.Diff(wantItem, got, EquateItems))
		}
	}
}

func areItems(a, b any) bool {
	_, ok1 := a.(vocab.Item)
	_, ok2 := b.(vocab.Item)
	return ok1 && ok2
}

func compareItems(x, y any) bool {
	var i1 vocab.Item
	var i2 vocab.Item
	if ic1, ok := x.(vocab.Item); ok {
		i1 = ic1
	}
	if ic2, ok := y.(vocab.Item); ok {
		i2 = ic2
	}
	return vocab.ItemsEqual(i1, i2) || vocab.ItemsEqual(i2, i1)
}

var EquateItems = cmp.FilterValues(areItems, cmp.Comparer(compareItems))
