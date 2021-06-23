package badger

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

const (
	clientsBucket   = "clients"
	authorizeBucket = "authorize"
	accessBucket    = "access"
	refreshBucket   = "refresh"
	folder          = "oauth"
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

func interfaceIsNil(c interface{}) bool {
	return reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()
}

type stor struct {
	d     *badger.DB
	m     sync.Mutex
	path  string
	host  string
	logFn log.LoggerFn
	errFn log.LoggerFn
	l     badger.Logger
}

type Config struct {
	Path  string
	Host  string
	LogFn log.LoggerFn
	ErrFn log.LoggerFn
}

func mkDirIfNotExists(p string) error {
	const defaultPerm = os.ModeDir | os.ModePerm | 0770
	p, _ = filepath.Abs(p)
	if fi, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(p, defaultPerm); err != nil {
				return err
			}
		}
	} else if !fi.IsDir() {
		return errors.Errorf("path exists, and is not a folder %s", p)
	}
	return nil
}

// New returns a new badger storage instance.
func New(c Config) *stor {
	if c.Path != "" {
		fullPath := path.Clean(c.Path)
		if err := mkDirIfNotExists(fullPath); err != nil {
			return nil
		}
		c.Path = path.Join(fullPath, folder)
	}
	b := stor{
		path:  c.Path,
		host:  c.Host,
		m:     sync.Mutex{},
		logFn: log.EmptyLogFn,
		errFn: log.EmptyLogFn,
	}
	if c.ErrFn != nil {
		b.errFn = c.ErrFn
	}
	if c.LogFn != nil {
		b.logFn = c.LogFn
	}
	b.l, _ = log.New(log.ErrFn(b.logFn), log.ErrFn(b.errFn))
	return &b
}

// Open opens the badger database if possible.
func (s *stor) Open() error {
	s.m.Lock()
	var err error
	c := badger.DefaultOptions(s.path).WithLogger(s.l)
	if s.path == "" {
		c.InMemory = true
	}
	s.d, err = badger.Open(c)
	if err != nil {
		err = errors.Annotatef(err, "unable to open storage")
	}
	return err
}

// Close closes the badger database if possible.
func (s *stor) Close() {
	if s.d == nil {
		return
	}
	s.d.Close()
	s.m.Unlock()
}

// Clone
func (s *stor) Clone() osin.Storage {
	s.Close()
	return s
}

func itemPath(pieces ...string) []byte {
	return []byte(path.Join(pieces...))
}

func (s stor) clientPath(id string) []byte {
	return itemPath(s.host, clientsBucket, id)
}

func (s stor) loadTxnClient(c *osin.DefaultClient, id string) func(tx *badger.Txn) error {
	fullPath := s.clientPath(id)
	return func(tx *badger.Txn) error {
		it, err := tx.Get(fullPath)
		if err != nil {
			return errors.NewNotFound(err, "Invalid path %s", fullPath)
		}
		return it.Value(loadRawClient(c))
	}
}

func loadRawClient(c *osin.DefaultClient) func(raw []byte) error {
	return func(raw []byte) error {
		cl := cl{}
		if err := json.Unmarshal(raw, &cl); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal client object")
		}
		c.Id = cl.Id
		c.Secret = cl.Secret
		c.RedirectUri = cl.RedirectUri
		c.UserData = cl.Extra
		return nil
	}
}

// GetClient
func (s *stor) GetClient(id string) (osin.Client, error) {
	if id == "" {
		return nil, errors.NotFoundf("Empty client id")
	}
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	c := new(osin.DefaultClient)
	if err := s.d.View(s.loadTxnClient(c, id)); err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *stor) UpdateClient(c osin.Client) error {
	if interfaceIsNil(c) {
		return nil
	}
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	cl := cl{
		Id:          c.GetId(),
		Secret:      c.GetSecret(),
		RedirectUri: c.GetRedirectUri(),
		Extra:       c.GetUserData(),
	}
	raw, err := json.Marshal(cl)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal client object")
	}
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Set(s.clientPath(c.GetId()), raw)
	})
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *stor) CreateClient(c osin.Client) error {
	return s.UpdateClient(c)
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *stor) RemoveClient(id string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(s.clientPath(id))
	})
}

func (s stor) authorizePath(code string) []byte {
	return itemPath(s.host, authorizeBucket, code)
}

// SaveAuthorize
func (s *stor) SaveAuthorize(data *osin.AuthorizeData) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()
	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId(), "code": data.Code}, err.Error())
		return errors.Annotatef(err, "Invalid user-data")
	}
	auth := auth{
		Client:      data.Client.GetId(),
		Code:        data.Code,
		ExpiresIn:   time.Duration(data.ExpiresIn),
		Scope:       data.Scope,
		RedirectURI: data.RedirectUri,
		State:       data.State,
		CreatedAt:   data.CreatedAt.UTC(),
		Extra:       data.UserData,
	}
	raw, err := json.Marshal(auth)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal authorization object")
	}
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Set(s.authorizePath(data.Code), raw)
	})
}

func (s stor) loadTxnAuthorize(a *osin.AuthorizeData, code string) func(tx *badger.Txn) error {
	fullPath := s.authorizePath(code)
	return func(tx *badger.Txn) error {
		it, err := tx.Get(fullPath)
		if err != nil {
			return errors.NotFoundf("Invalid path %s", fullPath)
		}
		return it.Value(loadRawAuthorize(a))
	}
}

func loadRawAuthorize(a *osin.AuthorizeData) func(raw []byte) error {
	return func(raw []byte) error {
		auth := auth{}
		if err := json.Unmarshal(raw, &auth); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal authorize object")
		}
		a.Code = auth.Code
		a.ExpiresIn = int32(auth.ExpiresIn)
		a.Scope = auth.Scope
		a.RedirectUri = auth.RedirectURI
		a.State = auth.State
		a.CreatedAt = auth.CreatedAt
		a.UserData = auth.Extra
		if len(auth.Code) > 0 {
			a.Client = &osin.DefaultClient{Id: auth.Code}
		}
		if a.ExpireAt().Before(time.Now().UTC()) {
			return errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		return nil
	}
}

// LoadAuthorize
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty authorize code")
	}
	data := osin.AuthorizeData{}
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	err = s.d.View(s.loadTxnAuthorize(&data, code))
	if err != nil {
		return nil, err
	}
	if data.Client != nil {
		client := new(osin.DefaultClient)
		if err = s.d.View(s.loadTxnClient(client, data.Client.GetId())); err == nil {
			data.Client = client
		}
	}
	return &data, err
}

// RemoveAuthorize
func (s *stor) RemoveAuthorize(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(s.authorizePath(code))
	})
}

func (s stor) accessPath(code string) []byte {
	return itemPath(s.host, accessBucket, code)
}

// SaveAccess
func (s *stor) SaveAccess(data *osin.AccessData) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	prev := ""
	authorizeData := &osin.AuthorizeData{}

	if data.AccessData != nil {
		prev = data.AccessData.AccessToken
	}

	if data.AuthorizeData != nil {
		authorizeData = data.AuthorizeData
	}

	if err != nil {
		s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
		return errors.Annotatef(err, "Invalid client user-data")
	}

	if data.RefreshToken != "" {
		s.d.Update(func(tx *badger.Txn) error {
			if err := s.saveRefresh(tx, data.RefreshToken, data.AccessToken); err != nil {
				s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
				return err
			}
			return nil
		})
	}

	if data.Client == nil {
		return errors.Newf("data.Client must not be nil")
	}

	acc := acc{
		Client:       data.Client.GetId(),
		Authorize:    authorizeData.Code,
		Previous:     prev,
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    time.Duration(data.ExpiresIn),
		Scope:        data.Scope,
		RedirectURI:  data.RedirectUri,
		CreatedAt:    data.CreatedAt.UTC(),
		Extra:        data.UserData,
	}
	raw, err := json.Marshal(acc)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal access object")
	}
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Set(s.accessPath(acc.AccessToken), raw)
	})
}

func loadRawAccess(a *osin.AccessData) func(raw []byte) error {
	return func(raw []byte) error {
		access := acc{}
		if err := json.Unmarshal(raw, &access); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal client object")
		}
		a.AccessToken = access.AccessToken
		a.RefreshToken = access.RefreshToken
		a.ExpiresIn = int32(access.ExpiresIn)
		a.Scope = access.Scope
		a.RedirectUri = access.RedirectURI
		a.CreatedAt = access.CreatedAt.UTC()
		a.UserData = access.Extra
		if len(access.Authorize) > 0 {
			a.AuthorizeData = &osin.AuthorizeData{Code: access.Authorize}
		}
		if len(access.Previous) > 0 {
			a.AccessData = &osin.AccessData{AccessToken: access.Previous}
		}
		return nil
	}
}

func (s stor) loadTxnAccess(a *osin.AccessData, token string) func(tx *badger.Txn) error {
	fullPath := s.accessPath(token)
	return func(tx *badger.Txn) error {
		it, err := tx.Get(fullPath)
		if err != nil {
			return errors.NewNotFound(err, "Invalid path %s", fullPath)
		}
		return it.Value(loadRawAccess(a))
	}
}

// LoadAccess
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty access code")
	}
	err := s.Open()
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()

	result := new(osin.AccessData)
	err = s.d.View(s.loadTxnAccess(result, code))

	if result.Client != nil && len(result.Client.GetId()) > 0 {
		client := new(osin.DefaultClient)
		if err = s.d.View(s.loadTxnClient(client, result.Client.GetId())); err == nil {
			result.Client = client
		}
	}
	if result.AuthorizeData != nil && len(result.AuthorizeData.Code) > 0 {
		auth := new(osin.AuthorizeData)
		if err = s.d.View(s.loadTxnAuthorize(auth, result.AuthorizeData.Code)); err == nil {
			result.AuthorizeData = auth
		}
	}
	if result.AccessData != nil && len(result.AccessData.AccessToken) > 0 {
		prev := new(osin.AccessData)
		if err = s.d.View(s.loadTxnAccess(prev, result.AuthorizeData.Code)); err == nil {
			result.AccessData = prev
		}
	}

	return result, err
}

// RemoveAccess
func (s *stor) RemoveAccess(token string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(s.accessPath(token))
	})
}

func (s stor) refreshPath(refresh string) []byte {
	return itemPath(s.host, refreshBucket, refresh)
}

// LoadRefresh
func (s *stor) LoadRefresh(token string) (*osin.AccessData, error) {
	if token == "" {
		return nil, errors.NotFoundf("Empty refresh token")
	}
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *stor) RemoveRefresh(token string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(s.refreshPath(token))
	})
}

func (s stor) saveRefresh(txn *badger.Txn, refresh, access string) (err error) {
	ref := ref{
		Access: access,
	}
	raw, err := json.Marshal(ref)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal refresh token object")
	}
	return txn.Set(s.refreshPath(refresh), raw)
}
