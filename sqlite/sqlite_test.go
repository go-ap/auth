package sqlite

import (
	"database/sql"
	"fmt"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"os"
	"path"
	"reflect"
	"testing"
	"time"
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

/*
create table client (
	code INTEGER primary key autoincrement,
	secret TEXT not null,
	redirect_uri TEXT not null,
	extra BLOB,
	code text
);
create unique index client_code_uindex on client (code);
*/
func initialize(t *testing.T, fns ...initFn) *stor {
	file := path.Join(os.TempDir(), fmt.Sprintf("test-%d.sqlite", time.Now().UTC().Unix()))
	os.RemoveAll(file)
	//cwd, _ := os.Getwd()
	//file := path.Join(cwd, "identifier.sqlite")
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatalf("Unable to initialize sqlite db: %s", err)
	}
	if err := Bootstrap(db, nil); err != nil {
		t.Fatalf("Unable to create tables: %s", err)
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
			name: "missing",
			args: args{ code: "missing" },
			want: nil,
			wantErr: false,
		},
		{
			name: "found",
			init: []initFn {
				func(db *sql.DB) error {
					_, err := db.Exec(createClient, "found", "secret", "redirURI", interface{}("extra123"))
					return err
				},
			},
			args: args{ code: "found" },
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
			defer s.Close()
			got, err := s.GetClient(tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (tt.want != nil && !reflect.DeepEqual(got, tt.want)) || got == nil{
				t.Errorf("GetClient() got = %v, want %v", got, tt.want)
			}
		})
	}
}
