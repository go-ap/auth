package sqlite

import (
	"database/sql"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

var (
	infFn = func(f logrus.Fields, m string, p ...interface{}) {
		logrus.WithFields(f).Infof(m, p...)
	}
	errFn = func(f logrus.Fields, m string, p ...interface{}) {
		logrus.WithFields(f).Errorf(m, p...)
	}
)

type initFn func(db *sql.DB) error

func testPath(t *testing.T) string {
	where := t.TempDir()
	return path.Join(where, path.Clean(t.Name()))
}

func initialize(t *testing.T, fns ...initFn) *stor {
	t.Skip("something is wrong with the temp location")
	file := testPath(t)
	os.RemoveAll(path.Dir(file))
	os.MkdirAll(path.Dir(file), 0770)
	if err := Bootstrap(Config{Path: file}, nil); err != nil {
		t.Fatalf("Unable to create tables: %s", err)
	}
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatalf("Unable to initialize sqlite db: %s", err)
	}
	for _, fn := range fns {
		if err := fn(db); err != nil {
			t.Fatalf("Unable to execute initializing function %s", err)
		}
	}
	return &stor{
		path:  file,
		conn:  db,
		logFn: infFn,
		errFn: errFn,
	}
}

func TestBootstrap(t *testing.T) {
	type args struct {
		conf Config
		cl   osin.Client
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Bootstrap(tt.args.conf, tt.args.cl); (err != nil) != tt.wantErr {
				t.Errorf("Bootstrap() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_Clone(t *testing.T) {
	tests := []struct {
		name string
		want osin.Storage
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t)
			if got := s.Clone(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Clone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_CreateClient(t *testing.T) {
	type args struct {
		c osin.Client
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.CreateClient(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("CreateClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_GetClient(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		want    osin.Client
		wantErr bool
	}{
		{
			name:    "missing",
			args:    args{code: "missing"},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found",
			init: []initFn{
				func(db *sql.DB) error {
					_, err := db.Exec(createClient, "found", "secret", "redirURI", interface{}("extra123"))
					return err
				},
			},
			args: args{code: "found"},
			want: &osin.DefaultClient{
				Id:          "found",
				Secret:      "secret",
				RedirectUri: "redirURI",
				UserData:    interface{}("extra123"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			got, err := s.GetClient(tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (tt.want != nil && !reflect.DeepEqual(got, tt.want)) || got == nil {
				t.Errorf("GetClient() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_ListClients(t *testing.T) {
	tests := []struct {
		name    string
		init    []initFn
		want    []osin.Client
		wantErr bool
	}{
		{
			name:    "missing",
			want:    []osin.Client{},
			wantErr: false,
		},
		{
			name: "found",
			init: []initFn{
				func(db *sql.DB) error {
					_, err := db.Exec(createClient, "found", "secret", "redirURI", interface{}("extra123"))
					return err
				},
			},
			want: []osin.Client{
				&osin.DefaultClient{
					Id:          "found",
					Secret:      "secret",
					RedirectUri: "redirURI",
					UserData:    interface{}("extra123"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			got, err := s.ListClients()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListClients() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListClients() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_LoadAccess(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		want    *osin.AccessData
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			got, err := s.LoadAccess(tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadAccess() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadAccess() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_LoadAuthorize(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		want    *osin.AuthorizeData
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			got, err := s.LoadAuthorize(tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadAuthorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadAuthorize() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_LoadRefresh(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		want    *osin.AccessData
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			got, err := s.LoadRefresh(tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadRefresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadRefresh() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_stor_Open(t *testing.T) {
	tests := []struct {
		name    string
		init    []initFn
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.Open(); (err != nil) != tt.wantErr {
				t.Errorf("Open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_RemoveAccess(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.RemoveAccess(tt.args.code); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_RemoveAuthorize(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.RemoveAuthorize(tt.args.code); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAuthorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_RemoveClient(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.RemoveClient(tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("RemoveClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_RemoveRefresh(t *testing.T) {
	type args struct {
		code string
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.RemoveRefresh(tt.args.code); (err != nil) != tt.wantErr {
				t.Errorf("RemoveRefresh() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_SaveAccess(t *testing.T) {
	type args struct {
		data *osin.AccessData
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.SaveAccess(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("SaveAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_SaveAuthorize(t *testing.T) {
	type args struct {
		data *osin.AuthorizeData
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.SaveAuthorize(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("SaveAuthorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_stor_UpdateClient(t *testing.T) {
	type args struct {
		c osin.Client
	}
	tests := []struct {
		name    string
		init    []initFn
		args    args
		wantErr bool
	}{
		{
			name:    "empty",
			args:    args{nil},
			wantErr: true,
		},
		{
			name: "plain",
			init: []initFn{
				func(db *sql.DB) error {
					_, err := db.Exec(createClient, "found", "test", "test", interface{}("test"))
					return err
				},
			},
			args: args{
				&osin.DefaultClient{
					Id:          "found",
					Secret:      "secret",
					RedirectUri: "redirURI",
					UserData:    interface{}("extra123"),
				},
			},
			wantErr: false,
		},
		{
			name: "plain",
			args: args{
				&osin.DefaultClient{
					Id:          "found",
					Secret:      "secret",
					RedirectUri: "redirURI",
					UserData:    nil,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := initialize(t, tt.init...)
			if err := s.UpdateClient(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("UpdateClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
