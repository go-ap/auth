package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
	"os"
	"path"
	"path/filepath"
	"time"
)

const defaultTimeout = 100*time.Millisecond

// New returns a new filesystem storage instance.
func New(c Config) *stor {
	p, _ := getFullPath(c)
	s := new(stor)
	s.path = p
	s.logFn = log.EmptyLogFn
	s.errFn = log.EmptyLogFn

	if c.ErrFn != nil {
		s.errFn = c.ErrFn
	}
	if c.LogFn != nil {
		s.logFn = c.LogFn
	}
	return s
}

type stor struct {
	path  string
	conn  *sql.DB
	logFn log.LoggerFn
	errFn log.LoggerFn
}

type Config struct {
	Path  string
	LogFn log.LoggerFn
	ErrFn log.LoggerFn
}

var errNotImplemented = errors.NotImplementedf("not implemented")

const (
	createClientTable = `CREATE TABLE IF NOT EXISTS "client"(
	"code" varchar constraint client_code_pkey PRIMARY KEY,
	"secret" varchar NOT NULL,
	"redirect_uri" varchar NOT NULL,
	"extra" BLOB DEFAULT '{}'
);
`

	createAuthorizeTable = `CREATE TABLE IF NOT EXISTS "authorize" (
	"code" varchar constraint authorize_code_pkey PRIMARY KEY,
	"client" varchar REFERENCES client(code),
	"expires_in" INTEGER,
	"scope" BLOB,
	"redirect_uri" varchar NOT NULL,
	"state" BLOB,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB DEFAULT '{}'
);
`

	createAccessTable = `CREATE TABLE IF NOT EXISTS "access" (
	"client" varchar REFERENCES client(code),
	"authorize" varchar REFERENCES authorize(code),
	"previous" varchar NOT NULL,
	"token" varchar NOT NULL,
	"refresh_token" varchar NOT NULL,
	"expires_in" INTEGER,
	"scope" BLOB DEFAULT NULL,
	"redirect_uri" varchar NOT NULL,
	"created_at" timestamp DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB DEFAULT '{}'
);
`

	createRefreshTable = `CREATE TABLE IF NOT EXISTS "refresh" (
	"access_token" TEXT NOT NULL REFERENCES access(token),
	"token" TEXT PRIMARY KEY NOT NULL
);
`

	tuneQuery = `
-- Use WAL mode (writers don't block readers):
-- PRAGMA journal_mode = 'WAL'; -- this locks during testing
-- Use memory as temporary storage:
PRAGMA temp_store = 2;
-- Faster synchronization that still keeps the data safe:
PRAGMA synchronous = 1;
-- Increase cache size (in this case to 64MB), the default is 2MB
PRAGMA cache_size = -64000;
`
)

func getAbsStoragePath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		var err error
		p, err = filepath.Abs(p)
		if err != nil {
			return "", err
		}
	}
	return p, nil
}

func mkDirIfNotExists(p string) error {
	fi, err := os.Stat(p)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(p, os.ModeDir|os.ModePerm|0700)
	}
	if err != nil {
		return err
	}
	fi, err = os.Stat(p)
	if err != nil {
		return err
	} else if !fi.IsDir() {
		return errors.Errorf("path exists, and is not a folder %s", p)
	}
	return nil
}

func getFullPath(c Config) (string, error) {
	p, _ := getAbsStoragePath(c.Path)
	if err := mkDirIfNotExists(path.Dir(p)); err != nil {
		return "memory", err
	}
	return path.Join(p, "oauth.sqlite"), nil
}

func Bootstrap(c Config, cl osin.Client) error {
	p, err := getFullPath(c)
	if err != nil {
		return err
	}
	os.RemoveAll(p)

	s := New(c)
	if err = s.Open(); err != nil {
		return err
	}
	defer s.Close()
	if _, err = s.conn.Query(createClientTable); err != nil {
		return err
	}
	if _, err = s.conn.Query(createAuthorizeTable); err != nil {
		return err
	}
	if _, err = s.conn.Query(createAccessTable); err != nil {
		return err
	}
	if _, err = s.conn.Query(createRefreshTable); err != nil {
		return err
	}
	if _, err = s.conn.Query(tuneQuery); err != nil {
		return err
	}
	return nil
}

// Clone
func (s *stor) Clone() osin.Storage {
	// NOTICE(marius): osin, uses this before saving the Authorization data, and it fails if the database
	// is not closed. This is why the tuneQuery journal_mode = WAL is needed.
	return s
}

// Close
func (s *stor) Close() {
	if s.conn == nil {
		return
	}
	if err := s.conn.Close(); err != nil {
		s.errFn(logrus.Fields{"err": err.Error()}, "unable to close sqlite db")
	}
	s.conn = nil
}

// Open
func (s *stor) Open() error {
	var err error
	if s.conn, err = sql.Open("sqlite", s.path); err != nil {
		return errors.Annotatef(err, "could not open sqlite connection")
	}
	return nil
}

const getClients = "SELECT code, secret, redirect_uri, extra FROM client;"

// ListClients
func (s *stor) ListClients() ([]osin.Client, error) {
	result := make([]osin.Client, 0)

	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	rows, err := s.conn.QueryContext(ctx, getClients)
	if err == sql.ErrNoRows || rows.Err() == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		s.errFn(logrus.Fields{"table": "client", "operation": "select"}, "%s", err)
		return result, errors.Annotatef(err, "Storage query error")
	}
	for rows.Next() {
		c := new(osin.DefaultClient)
		err = rows.Scan(&c.Id, &c.Secret, &c.RedirectUri, &c.UserData)
		if err != nil {
			continue
		}
		result = append(result, c)
	}

	return result, err
}

const getClientSQL = "SELECT code, secret, redirect_uri, extra FROM client WHERE code=?;"

func getClient(conn *sql.DB, id string) (osin.Client, error) {
	var c *osin.DefaultClient
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	rows, err := conn.QueryContext(ctx, getClientSQL, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFound(err, "")
		}
		//s.errFn(logrus.Fields{"code": id, "table": "client", "operation": "select"}, "%s", err)
		return nil, errors.Annotatef(err, "Storage query error")
	}
	for rows.Next() {
		c = new(osin.DefaultClient)
		err = rows.Scan(&c.Id, &c.Secret, &c.RedirectUri, &c.UserData)
		if err != nil {
			return nil, errors.Annotatef(err, "Unable to load client information")
		}
	}

	return c, nil
}

// GetClient
func (s *stor) GetClient(id string) (osin.Client, error) {
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	return getClient(s.conn, id)
}

const updateClient = "UPDATE client SET (secret, redirect_uri, extra) = (?, ?, ?) WHERE code=?"
const updateClientNoExtra = "UPDATE client SET (secret, redirect_uri) = (?, ?) WHERE code=?"

// UpdateClient
func (s *stor) UpdateClient(c osin.Client) error {
	if c == nil {
		return errors.Newf("invalid nil client to update")
	}
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()

	data, err := assertToBytes(c.GetUserData())
	if err != nil {
		s.errFn(logrus.Fields{"id": c.GetId()}, err.Error())
		return err
	}

	params := []interface{}{
		c.GetSecret(),
		c.GetRedirectUri(),
	}
	q := updateClientNoExtra
	if data != nil {
		q = updateClient
		params = append(params, interface{}(data))
	}
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if _, err := s.conn.ExecContext(ctx, q, params...); err != nil {
		s.errFn(logrus.Fields{"id": c.GetId(), "table": "client", "operation": "update"}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const createClientNoExtra = "INSERT INTO client (code, secret, redirect_uri) VALUES (?, ?, ?)"
const createClient = "INSERT INTO client (code, secret, redirect_uri, extra) VALUES (?, ?, ?, ?)"

// CreateClient
func (s *stor) CreateClient(c osin.Client) error {
	if c == nil {
		return errors.Newf("invalid nil client to create")
	}
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()

	data, err := assertToBytes(c.GetUserData())
	if err != nil {
		s.errFn(logrus.Fields{"id": c.GetId()}, err.Error())
		return err
	}
	params := []interface{}{
		c.GetId(),
		c.GetSecret(),
		c.GetRedirectUri(),
	}
	q := createClientNoExtra
	if data != nil {
		q = createClient
		params = append(params, interface{}(data))
	}

	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if _, err := s.conn.ExecContext(ctx, q, params...); err != nil {
		s.errFn(logrus.Fields{"id": c.GetId(), "redirect_uri": c.GetRedirectUri(), "table": "client", "operation": "insert"}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const removeClient = "DELETE FROM client WHERE code=?"

// RemoveClient
func (s *stor) RemoveClient(id string) error {
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if _, err := s.conn.ExecContext(ctx, removeClient, id); err != nil {
		s.errFn(logrus.Fields{"id": id, "table": "client", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"id": id}, "removed client")
	return nil
}

const saveAuthorizeNoExtra = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at) 
	VALUES (?, ?, ?, ?, ?, ?, ?);
`
const saveAuthorize = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at, extra)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

// SaveAuthorize saves authorize data.
func (s *stor) SaveAuthorize(data *osin.AuthorizeData) error {
	if data == nil {
		return errors.Newf("invalid nil authorize to save")
	}
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()
	extra, err := assertToBytes(data.UserData)
	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "code": data.Code}, err.Error())
		return err
	}

	q := saveAuthorizeNoExtra
	var params = []interface{}{
		data.Client.GetId(),
		data.Code,
		data.ExpiresIn,
		data.Scope,
		data.RedirectUri,
		data.State,
		data.CreatedAt.UTC(),
	}
	if extra != nil {
		q = saveAuthorize
		params = append(params, extra)
	}

	tx, err := s.conn.Begin()
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if _, err = tx.ExecContext(ctx, q, params...); err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "table": "authorize", "operation": "insert", "code": data.Code}, err.Error())
		return errors.Annotatef(err, "")
	}
	if err = tx.Commit(); err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const loadAuthorizeSQL = "SELECT client, code, expires_in, scope, redirect_uri, state, created_at, extra FROM authorize WHERE code=? LIMIT 1"

func loadAuthorize(conn *sql.DB, code string) (*osin.AuthorizeData, error) {
	var a *osin.AuthorizeData

	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	rows, err := conn.QueryContext(ctx, loadAuthorizeSQL, code)
	if err == sql.ErrNoRows {
		return nil, errors.NotFoundf("")
	} else if err != nil {
		//s.errFn(logrus.Fields{"code": code, "table": "authorize", "operation": "select"}, err.Error())
		return nil, errors.Annotatef(err, "")
	}

	var client string
	for rows.Next() {
		a = new(osin.AuthorizeData)
		var createdAt string
		err = rows.Scan(&client, &a.Code, &a.ExpiresIn, &a.Scope, &a.RedirectUri, &a.State, &createdAt, &a.UserData)
		if err != nil {
			return nil, errors.Annotatef(err, "unable to load authorize data")
		}

		if len(client) > 0 {
			a.Client, _ = getClient(conn, client)
		}

		a.CreatedAt, _ = time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", createdAt)
		if a.ExpireAt().Before(time.Now().UTC()) {
			//s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil, errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		break
	}

	return a, nil

}

// LoadAuthorize looks up AuthorizeData by a code.
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	return loadAuthorize(s.conn, code)
}

const removeAuthorize = "DELETE FROM authorize WHERE code=?"

// RemoveAuthorize revokes or deletes the authorization code.
func (s *stor) RemoveAuthorize(code string) error {
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if _, err := s.conn.ExecContext(ctx, removeAuthorize, code); err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "authorize", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed authorization token")
	return nil
}

const saveAccess = `INSERT INTO access (client, authorize, previous, token, refresh_token, expires_in, scope, redirect_uri, created_at, extra) 
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// SaveAccess writes AccessData.
func (s *stor) SaveAccess(data *osin.AccessData) error {
	prev := ""
	authorizeData := &osin.AuthorizeData{}

	if data.AccessData != nil {
		prev = data.AccessData.AccessToken
	}

	if data.AuthorizeData != nil {
		authorizeData = data.AuthorizeData
	}

	extra, err := assertToBytes(data.UserData)
	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return err
	}
	if err = s.Open(); err != nil {
		return err
	}
	defer s.Close()

	tx, err := s.conn.Begin()
	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return errors.Annotatef(err, "")
	}

	if data.RefreshToken != "" {
		if err := s.saveRefresh(tx, data.RefreshToken, data.AccessToken); err != nil {
			s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
			return err
		}
	}
	params := []interface{}{
		data.Client.GetId(),
		authorizeData.Code,
		prev,
		data.AccessToken,
		data.RefreshToken,
		data.ExpiresIn,
		data.Scope,
		data.RedirectUri,
		data.CreatedAt.UTC(),
		extra,
	}

	if data.Client == nil {
		return errors.Newf("data.Client must not be nil")
	}
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	_, err = tx.ExecContext(ctx, saveAccess, params...)
	if err != nil {
		if rbe := tx.Rollback(); rbe != nil {
			s.errFn(logrus.Fields{"id": data.Client.GetId()}, rbe.Error())
			return errors.Annotatef(rbe, "")
		}
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return errors.Annotatef(err, "")
	}

	if err = tx.Commit(); err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return errors.Annotatef(err, "")
	}

	return nil
}

const loadAccessSQL = `SELECT client, authorize, previous, token, refresh_token, expires_in, scope, redirect_uri, created_at, extra 
	FROM access WHERE token=? LIMIT 1`

func loadAccess(conn *sql.DB, code string) (*osin.AccessData, error) {
	var a *osin.AccessData
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	rows, err := conn.QueryContext(ctx, loadAccessSQL, code)
	if err == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		return nil, errors.Annotatef(err, "")
	}
	for rows.Next() {
		a = new(osin.AccessData)
		var client, authorize, prev, createdAt string
		err = rows.Scan(&client, &authorize, &prev, &a.AccessToken, &a.RefreshToken, &a.ExpiresIn, &a.RedirectUri,
			&a.Scope, &createdAt, &a.UserData)
		if err != nil {
			return nil, errors.Annotatef(err, "unable to load authorize data")
		}

		if len(client) > 0 {
			a.Client, _ = getClient(conn, client)
		}
		if len(authorize) > 0 {
			a.AuthorizeData, _ = loadAuthorize(conn, authorize)
		}
		if len(prev) > 0 {
			a.AccessData, _ = loadAccess(conn, prev)
		}

		a.CreatedAt, _ = time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", createdAt)
		if a.ExpireAt().Before(time.Now().UTC()) {
			//s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil, errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		break
	}

	return a, nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	return loadAccess(s.conn, code)
}

const removeAccess = "DELETE FROM access WHERE token=?"

// RemoveAccess revokes or deletes an AccessData.
func (s *stor) RemoveAccess(code string) error {
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	_, err := s.conn.ExecContext(ctx, removeAccess, code)
	if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "access", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed access token")
	return nil
}

const loadRefresh = "SELECT access_token FROM refresh WHERE token=? LIMIT 1"

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *stor) LoadRefresh(code string) (*osin.AccessData, error) {
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	var access string
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	if err := s.conn.QueryRowContext(ctx, loadRefresh, code).Scan(access); err == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		return nil, errors.Annotatef(err, "")
	}

	return loadAccess(s.conn, access)
}

const removeRefresh = "DELETE FROM refresh WHERE token=?"

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *stor) RemoveRefresh(code string) error {
	if err := s.Open(); err != nil {
		return err
	}
	defer s.Close()
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	_, err := s.conn.ExecContext(ctx, removeRefresh, code)
	if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "refresh", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed refresh token")
	return nil
}

const saveRefresh = "INSERT INTO refresh (token, access_token) VALUES (?, ?)"

func (s *stor) saveRefresh(tx *sql.Tx, refresh, access string) (err error) {
	ctx, _ := context.WithTimeout(context.Background(), defaultTimeout)
	_, err = tx.ExecContext(ctx, saveRefresh, refresh, access)
	if err != nil {
		if rbe := tx.Rollback(); rbe != nil {
			s.errFn(logrus.Fields{"code": access, "table": "refresh", "operation": "insert"}, rbe.Error())
			return errors.Annotatef(rbe, "")
		}
		return errors.Annotatef(err, "")
	}
	return nil
}

func assertToBytes(in interface{}) ([]byte, error) {
	var ok bool
	var data string
	if in == nil {
		return nil, nil
	} else if data, ok = in.(string); ok {
		return []byte(data), nil
	} else if byt, ok := in.([]byte); ok {
		return byt, nil
	} else if byt, ok := in.(json.RawMessage); ok {
		return byt, nil
	} else if str, ok := in.(fmt.Stringer); ok {
		return []byte(str.String()), nil
	}
	return nil, errors.Errorf(`Could not assert "%v" to string`, in)
}
