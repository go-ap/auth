package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client"
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
			args: args{cl: nil, initFns: []InitFn{WithStorage(new(mockSt))}},
			want: config{st: new(mockSt), l: lw.Nil()},
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
	if !cmp.Equal(xe.st, ye.st) {
		return false
	}
	if !reflect.ValueOf(xe.l).Equal(reflect.ValueOf(ye.l)) {
		return false
	}
	return slices.Equal(xe.ignore, ye.ignore)
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

type mockSt struct{}

func (ms *mockSt) Load(_ vocab.IRI, _ ...filters.Check) (vocab.Item, error) {
	return nil, nil
}

func (ms *mockSt) LoadAccess(_ string) (*osin.AccessData, error) {
	return nil, nil
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
			args: args{cl: nil, initFns: []InitFn{WithStorage(new(mockSt))}},
			want: actorResolver{st: new(mockSt), l: lw.Nil()},
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

func mockReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
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
			a:       actorResolver{st: new(mockSt), l: lw.Dev(lw.SetOutput(t.Output()))},
			r:       mockReq(),
			want:    AnonymousActor,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.a.Verify(tt.r)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Verify() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Verify() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
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
