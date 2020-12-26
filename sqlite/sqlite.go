package sqlite

import (
	"database/sql"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
	"time"
)

type cl struct {
	Id          string
	Secret      string
	RedirectUri string
	Extra       interface{}
}

type auth struct {
	Client      string
	Code        string
	ExpiresIn   time.Duration
	Scope       string
	RedirectURI string
	State       string
	CreatedAt   time.Time
	Extra       interface{}
}

type acc struct {
	Client       string
	Authorize    string
	Previous     string
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
	Scope        string
	RedirectURI  string
	CreatedAt    time.Time
	Extra        interface{}
}

type ref struct {
	Access string
}

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
	"id" INTEGER PRIMARY KEY ASC AUTOINCREMENT,
	"code" TEXT UNIQUE NOT NULL,
	"secret" TEXT NOT NULL,
	"redirect_uri" TEXT NOT NULL,
	"extra" BLOB
);`

const createAuthorizeTable = `CREATE TABLE "authorize" (
	"id" INTEGER PRIMARY KEY ASC AUTOINCREMENT,
	"client_id" INTEGER REFERENCES client(code),
	"code" TEXT UNIQUE NOT NULL,
	"expires_in" INTEGER,
	"scope" BLOB,
	"redirect_uri" TEXT NOT NULL,
	"state" BLOB,
	"created_at" DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB
);`

const createAccessTable = `CREATE TABLE "access" (
	"id" INTEGER PRIMARY KEY ASC AUTOINCREMENT,
	"client_id" INTEGER REFERENCES client(id),
	"authorize_id" INTEGER REFERENCES authorize(id),
	"previous" TEXT NOT NULL,
	"access_token" TEXT NOT NULL,
	"refresh_token" TEXT NOT NULL,
	"expires_in" INTEGER,
	"scope" BLOB,
	"redirect_uri" TEXT NOT NULL,
	"created_at" DEFAULT CURRENT_TIMESTAMP,
	"extra" BLOB
);`

const createRefreshTable = `CREATE TABLE "refresh" (
	"id" INTEGER PRIMARY KEY ASC AUTOINCREMENT,
	"access" TEXT NOT NULL REFERENCES access(access_token),
	"token" TEXT NOT NULL
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
	return nil, errNotImplemented
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

// UpdateClient
func (s *stor) UpdateClient(c osin.Client) error {
	return errNotImplemented
}

const createClient = "INSERT INTO client (code, secret, redirect_uri, extra) VALUES (?, ?, ?, ?)"

// CreateClient
func (s *stor) CreateClient(c osin.Client) error {
	return errNotImplemented
}

const removeClient = "DELETE FROM client WHERE code=?"

// RemoveClient
func (s *stor) RemoveClient(id string) error {
	return errNotImplemented
}

const saveAuthorize = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at, extra) 
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// SaveAuthorize saves authorize data.
func (s *stor) SaveAuthorize(data *osin.AuthorizeData) error {
	return errNotImplemented
}

const loadAuthorize = "SELECT client, code, expires_in, scope, redirect_uri, state, created_at, extra FROM authorize WHERE code=? LIMIT 1"

// LoadAuthorize looks up AuthorizeData by a code.
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	return nil, errNotImplemented
}

const removeAuthorize = "DELETE FROM authorize WHERE code=?"

// RemoveAuthorize revokes or deletes the authorization code.
func (s *stor) RemoveAuthorize(code string) error {
	return errNotImplemented
}

const saveAccess = `INSERT INTO access (client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra) 
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// SaveAccess writes AccessData.
func (s *stor) SaveAccess(data *osin.AccessData) error {
	return errNotImplemented
}

const loadAccess = `SELECT client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra 
	FROM access WHERE access_token=? LIMIT 1`

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	return nil, errNotImplemented
}

const removeAccess = "DELETE FROM access WHERE access_token=?"

// RemoveAccess revokes or deletes an AccessData.
func (s *stor) RemoveAccess(code string) error {
	return errNotImplemented
}

const loadRefresh = "SELECT access FROM refresh WHERE token=? LIMIT 1"

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *stor) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, errNotImplemented
}

const removeRefresh = "DELETE FROM refresh WHERE token=?"

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *stor) RemoveRefresh(code string) error {
	return errNotImplemented
}

const saveRefresh = "INSERT INTO refresh (token, access) VALUES (?, ?)"
