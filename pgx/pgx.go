package pgx

import (
	"encoding/json"
	"fmt"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/jackc/pgx"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
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

type Config struct {
	Enabled bool
	Host    string
	Port    int64
	User    string
	Pw      string
	Name    string
	LogFn   log.LoggerFn
	ErrFn   log.LoggerFn
}

var errNotImplemented = errors.NotImplementedf("not implemented")

// stor implements interface osin.Storage
type stor struct {
	conn  *pgx.Conn
	conf  Config
	logFn log.LoggerFn
	errFn log.LoggerFn
}

// New returns a new postgres storage instance.
func New(c Config) *stor {
	s := stor{
		conf:  c,
		logFn: log.EmptyLogFn,
		errFn: log.EmptyLogFn,
	}
	if c.ErrFn != nil {
		s.errFn = c.ErrFn
	}
	if c.LogFn != nil {
		s.logFn = c.LogFn
	}
	return &s
}

func Bootstrap(conn *pgx.Conn, cl osin.Client) error {
	return nil
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *stor) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *stor) Close() {
	if s.conn == nil {
		return
	}
	s.conn.Close()
}

type logger struct {
	logFn log.LoggerFn
}

func (p logger) Log(level pgx.LogLevel, msg string, data map[string]interface{}) {
	p.logFn(data, "%s: %s", level, msg)
}

func (s *stor) Open() error {
	var err error
	conf := pgx.ConnConfig{
		Host:     s.conf.Host,
		Port:     uint16(s.conf.Port),
		Database: s.conf.Name,
		User:     s.conf.User,
		Password: s.conf.Pw,
		Logger:   logger{s.logFn},
	}
	if s.conn, err = pgx.Connect(conf); err != nil {
		return errors.Annotatef(err, "could not open pgx connection")
	}
	return nil
}

const getClients = "SELECT id, secret, redirect_uri, extra FROM client;"
// ListClients
func (s *stor) ListClients() ([]osin.Client, error) {
	result := make([]osin.Client, 0)
	rows, err := s.conn.Query(getClients)
	if err == pgx.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		s.errFn(logrus.Fields{"table": "client", "operation": "select"}, "%s", err)
		return result, errors.Annotatef(err, "Storage query error")
	}
	for rows.Next() {
		var cl cl
		c := new(osin.DefaultClient)
		err = rows.Scan(&cl)
		if err != nil {
			continue
		}
		c.Id = cl.Id
		c.Secret = cl.Secret
		c.RedirectUri = cl.RedirectUri
		c.UserData = cl.Extra
		result = append(result, c)
	}

	return result, err
}

const getClient = "SELECT id, secret, redirect_uri, extra FROM client WHERE id=?"
// GetClient loads the client by id
func (s *stor) GetClient(id string) (osin.Client, error) {
	if id == "" {
		return nil, errors.NotFoundf("Empty client id")
	}
	var cl cl
	var c osin.DefaultClient
	if err := s.conn.QueryRow(getClient, id).Scan(&cl); err == pgx.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		s.errFn(logrus.Fields{"id": id, "table": "client", "operation": "select"}, "%s", err)
		return &c, errors.Annotatef(err, "Storage query error")
	}
	c.Id = cl.Id
	c.Secret = cl.Secret
	c.RedirectUri = cl.RedirectUri
	c.UserData = cl.Extra

	return &c, nil
}

const updateClient = "UPDATE client SET (secret, redirect_uri, extra) = (?2, ?3, ?4) WHERE id=?1"
// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *stor) UpdateClient(c osin.Client) error {
	if c == nil {
		return errors.Newf("invalid nil client to update")
	}
	data, err := assertToBytes(c.GetUserData())
	if err != nil {
		s.errFn(logrus.Fields{"id": c.GetId()}, err.Error())
		return err
	}

	if _, err := s.conn.Exec(updateClient, c.GetId(), c.GetSecret(), c.GetRedirectUri(), data); err != nil {
		s.errFn(logrus.Fields{"id": c.GetId(), "table": "client", "operation": "update"}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const createClient = "INSERT INTO client (id, secret, redirect_uri, extra) VALUES (?0, ?1, ?2, ?3)"
// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *stor) CreateClient(c osin.Client) error {
	if c == nil {
		return errors.Newf("invalid nil client to create")
	}
	data, err := assertToBytes(c.GetUserData())
	if err != nil {
		s.errFn(logrus.Fields{"id": c.GetId()}, err.Error())
		return err
	}

	if _, err := s.conn.Exec(createClient, c.GetId(), c.GetSecret(), c.GetRedirectUri(), data); err != nil {
		s.errFn(logrus.Fields{"id": c.GetId(), "redirect_uri": c.GetRedirectUri(), "table": "client", "operation": "insert"}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const removeClient = "DELETE FROM client WHERE id=?"
// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *stor) RemoveClient(id string) error {
	if _, err := s.conn.Exec(removeClient, id); err != nil {
		s.errFn(logrus.Fields{"id": id, "table": "client", "operation": "delete"}, err.Error())
		return errors.Annotatef(err, "")
	}
	s.logFn(logrus.Fields{"id": id}, "removed client")
	return nil
}

const saveAuthorize = `INSERT INTO authorize (client, code, expires_in, scope, redirect_uri, state, created_at, extra) 
	VALUES (?0, ?1, ?2, ?3, ?4, ?5, ?6, ?7)`
// SaveAuthorize saves authorize data.
func (s *stor) SaveAuthorize(data *osin.AuthorizeData) (err error) {
	extra, err := assertToBytes(data.UserData)
	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "code": data.Code}, err.Error())
		return err
	}

	var params = []interface{}{
		data.Client.GetId(),
		data.Code,
		data.ExpiresIn,
		data.Scope,
		data.RedirectUri,
		data.State,
		data.CreatedAt.UTC(),
		extra,
	}

	if _, err = s.conn.Exec(saveAuthorize, params...); err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "table": "authorize", "operation": "insert", "code": data.Code}, err.Error())
		return errors.Annotatef(err, "")
	}
	return nil
}

const loadAuthorize = "SELECT client, code, expires_in, scope, redirect_uri, state, created_at, extra FROM authorize WHERE code=? LIMIT 1"
// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty authorize code")
	}
	var data osin.AuthorizeData

	var auth auth
	if err := s.conn.QueryRow(loadAuthorize, code).Scan(&auth); err == pgx.ErrNoRows {
		return nil, errors.NotFoundf("")
	} else if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "authorize", "operation": "select"}, err.Error())
		return nil, errors.Annotatef(err, "")
	}
	data.Code = auth.Code
	data.ExpiresIn = int32(auth.ExpiresIn)
	data.Scope = auth.Scope
	data.RedirectUri = auth.RedirectURI
	data.State = auth.State
	data.CreatedAt = auth.CreatedAt
	data.UserData = auth.Extra

	c, err := s.GetClient(auth.Client)
	if err != nil {
		return nil, err
	}

	if data.ExpireAt().Before(time.Now().UTC()) {
		s.errFn(logrus.Fields{"code": code}, err.Error())
		return nil, errors.Errorf("Token expired at %s.", data.ExpireAt().String())
	}

	data.Client = c
	return &data, nil
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
	VALUES (?0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *stor) SaveAccess(data *osin.AccessData) (err error) {
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

	if data.Client == nil {
		return errors.Newf("data.Client must not be nil")
	}
	_, err = tx.Exec(saveAccess, data.Client.GetId(), authorizeData.Code, prev, data.AccessToken, data.RefreshToken, data.ExpiresIn, data.Scope, data.RedirectUri, data.CreatedAt.UTC(), extra)
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
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty access code")
	}
	var result osin.AccessData

	var acc acc
	if err := s.conn.QueryRow(loadAccess, code).Scan(&acc); err == pgx.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {
		return nil, errors.Annotatef(err, "")
	}
	result.AccessToken = acc.AccessToken
	result.RefreshToken = acc.RefreshToken
	result.ExpiresIn = int32(acc.ExpiresIn)
	result.Scope = acc.Scope
	result.RedirectUri = acc.RedirectURI
	result.CreatedAt = acc.CreatedAt.UTC()
	result.UserData = acc.Extra
	client, err := s.GetClient(acc.Client)
	if err != nil {
		s.errFn(logrus.Fields{"code": code, "table": "access", "operation": "select"}, err.Error())
		return nil, err
	}

	result.Client = client
	result.AuthorizeData, _ = s.LoadAuthorize(acc.Authorize)
	prevAccess, _ := s.LoadAccess(acc.Previous)
	result.AccessData = prevAccess
	return &result, nil
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
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *stor) LoadRefresh(code string) (*osin.AccessData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty refresh code")
	}
	var ref ref
	if err := s.conn.QueryRow(loadRefresh, code).Scan(&ref); err == pgx.ErrNoRows {
		return nil, errors.NewNotFound(err, "")
	} else if err != nil {

		return nil, errors.Annotatef(err, "")
	}
	return s.LoadAccess(ref.Access)
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

const saveRefresh = "INSERT INTO refresh (token, access) VALUES (?0, ?1)"
func (s *stor) saveRefresh(tx *pgx.Tx, refresh, access string) (err error) {
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
