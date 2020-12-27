package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
	"time"
)

// New returns a new filesystem storage instance.
func New(c Config) *stor {
	s := new(stor)
	s.path = c.Path
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

const createClientTable = `CREATE TABLE "client"(
	"code" TEXT PRIMARY KEY NOT NULL,
	"secret" TEXT NOT NULL,
	"redirect_uri" TEXT NOT NULL,
	"extra" BLOB DEFAULT '{}'
);`

const createAuthorizeTable = `CREATE TABLE "authorize" (
	"code" TEXT PRIMARY KEY NOT NULL,
	"client" INTEGER REFERENCES client(code),
	"expires_in" INTEGER,
	"scope" BLOB,
	"redirect_uri" TEXT NOT NULL,
	"state" BLOB,
	"created_at" DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB DEFAULT '{}'
);`

const createAccessTable = `CREATE TABLE "access" (
	"client" INTEGER REFERENCES client(code),
	"authorize" INTEGER REFERENCES authorize(code),
	"previous" TEXT NOT NULL,
	"access_token" TEXT NOT NULL,
	"refresh_token" TEXT NOT NULL,
	"expires_in" INTEGER,
	"scope" BLOB DEFAULT NULL,
	"redirect_uri" TEXT NOT NULL,
	"created_at" DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB DEFAULT '{}'
);`

const createRefreshTable = `CREATE TABLE "refresh" (
	"access_token" TEXT NOT NULL REFERENCES access(access_token),
	"token" TEXT PRIMARY KEY NOT NULL
);`

func Bootstrap(db *sql.DB, cl osin.Client) error {
	if _, err := db.Query(createClientTable); err != nil {
		return err
	}
	if _, err := db.Query(createAuthorizeTable); err != nil {
		return err
	}
	if _, err := db.Query(createAccessTable); err != nil {
		return err
	}
	if _, err := db.Query(createRefreshTable); err != nil {
		return err
	}

	return nil
}

// Clone
func (s *stor) Clone() osin.Storage {
	return s
}

// Close
func (s *stor) Close() {
	if s.conn == nil {
		return
	}
	s.conn.Close()
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
	rows, err := s.conn.Query(getClients)
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

const getClient = "SELECT code, secret, redirect_uri, extra FROM client WHERE code=?;"

// GetClient
func (s *stor) GetClient(id string) (osin.Client, error) {
	var c *osin.DefaultClient
	rows, err := s.conn.Query(getClient, id)
	if err == sql.ErrNoRows || rows.Err() == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		s.errFn(logrus.Fields{"code": id, "table": "client", "operation": "select"}, "%s", err)
		return c, errors.Annotatef(err, "Storage query error")
	}
	for rows.Next() {
		c = new(osin.DefaultClient)
		err = rows.Scan(&c.Id, &c.Secret, &c.RedirectUri, &c.UserData)
		if err != nil {
			break
		}
	}

	return c, err
}

const updateClient = "UPDATE client SET (secret, redirect_uri, extra) = (?, ?, ?) WHERE code=?"
const updateClientNoExtra = "UPDATE client SET (secret, redirect_uri) = (?, ?) WHERE code=?"

// UpdateClient
func (s *stor) UpdateClient(c osin.Client) error {
	if c == nil {
		return errors.Newf("invalid nil client to update")
	}
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
	if _, err := s.conn.Exec(q, params...); err != nil {
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

	if _, err := s.conn.Exec(q, params...); err != nil {
		s.errFn(logrus.Fields{"id": c.GetId(), "redirect_uri": c.GetRedirectUri(), "table": "client", "operation": "insert"}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const removeClient = "DELETE FROM client WHERE code=?"

// RemoveClient
func (s *stor) RemoveClient(id string) error {
	if _, err := s.conn.Exec(removeClient, id); err != nil {
		s.errFn(logrus.Fields{"id": id, "table": "client", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"id": id}, "removed client")
	return nil
}

const saveAuthorizeNoExtra = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at ) 
	VALUES (?, ?, ?, ?, ?, ?, ?);`
const saveAuthorize = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at, extra)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

// SaveAuthorize saves authorize data.
func (s *stor) SaveAuthorize(data *osin.AuthorizeData) error {
	if data == nil {
		return errors.Newf("invalid nil authorize to save")
	}
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

	if _, err = s.conn.Exec(q, params...); err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "table": "authorize", "operation": "insert", "code": data.Code}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const loadAuthorize = "SELECT client, code, expires_in, scope, redirect_uri, state, created_at, extra FROM authorize WHERE code=? LIMIT 1"

// LoadAuthorize looks up AuthorizeData by a code.
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	var a *osin.AuthorizeData

	rows, err := s.conn.Query(loadAuthorize, code)
	if err == sql.ErrNoRows {
		return nil, errors.NotFoundf("")
	} else if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "authorize", "operation": "select"}, err.Error())
		return nil, errors.Annotatef(err, "")
	}

	var client string
	for rows.Next() {
		a = new(osin.AuthorizeData)
		err = rows.Scan(&client, &a.Code, &a.ExpiresIn, &a.Scope, &a.RedirectUri, &a.State, &a.CreatedAt, &a.UserData)
		if err != nil {
			return nil, errors.Annotatef(err, "unable to load authorize data")
		}

		if len(client) > 0 {
			a.Client, _ = s.GetClient(client)
		}

		if a.ExpireAt().Before(time.Now().UTC()) {
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil, errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		break
	}

	return a, nil
}

const removeAuthorize = "DELETE FROM authorize WHERE code=?"

// RemoveAuthorize revokes or deletes the authorization code.
func (s *stor) RemoveAuthorize(code string) error {
	if _, err := s.conn.Exec(removeAuthorize, code); err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "authorize", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed authorization token")
	return nil
}

const saveAccess = `INSERT INTO access (client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra) 
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
	_, err = tx.Exec(saveAccess, params...)
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

const loadAccess = `SELECT client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra 
	FROM access WHERE access_token=? LIMIT 1`

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	var a *osin.AccessData
	rows, err := s.conn.Query(loadAccess, code)
	if err == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		return nil, errors.Annotatef(err, "")
	}
	for rows.Next() {
		a = new(osin.AccessData)
		var client, authorize, prev string
		err = rows.Scan(&client, &authorize, &prev, &a.AccessToken, &a.RefreshToken, &a.ExpiresIn, &a.Scope, &a.CreatedAt, &a.UserData)
		if err != nil {
			return nil, errors.Annotatef(err, "unable to load authorize data")
		}

		if len(client) > 0 {
			a.Client, _ = s.GetClient(client)
		}
		if len(authorize) > 0 {
			a.AuthorizeData, _ = s.LoadAuthorize(authorize)
		}
		if len(prev) > 0 {
			a.AccessData, _ = s.LoadAccess(prev)
		}

		if a.ExpireAt().Before(time.Now().UTC()) {
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil, errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		break
	}

	return a, nil
}

const removeAccess = "DELETE FROM access WHERE access_token=?"

// RemoveAccess revokes or deletes an AccessData.
func (s *stor) RemoveAccess(code string) error {
	_, err := s.conn.Exec(removeAccess, code)
	if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "access", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed access token")
	return nil
}

const loadRefresh = "SELECT access FROM refresh WHERE token=? LIMIT 1"

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *stor) LoadRefresh(code string) (*osin.AccessData, error) {
	var access string
	if err := s.conn.QueryRow(loadRefresh, code).Scan(access); err == sql.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		return nil, errors.Annotatef(err, "")
	}

	return s.LoadAccess(access)
}

const removeRefresh = "DELETE FROM refresh WHERE token=?"

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *stor) RemoveRefresh(code string) error {
	_, err := s.conn.Exec(removeRefresh, code)
	if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "refresh", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"code": code}, "removed refresh token")
	return nil
}

const saveRefresh = "INSERT INTO refresh (token, access) VALUES (?, ?)"

func (s *stor) saveRefresh(tx *sql.Tx, refresh, access string) (err error) {
	_, err = tx.Exec(saveRefresh, refresh, access)
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
