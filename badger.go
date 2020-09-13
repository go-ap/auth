package auth

import (
	"encoding/json"
	"github.com/dgraph-io/badger"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"path"
	"sync"
	"time"
)

type badgerStorage struct {
	d     *badger.DB
	m     sync.Mutex
	path  string
	host  string
	logFn loggerFn
	errFn loggerFn
}

type BadgerConfig struct {
	Path  string
	LogFn loggerFn
	ErrFn loggerFn
}

// NewBadgerStore returns a new badger storage instance.
func NewBadgerStore(c FSConfig) *badgerStorage {
	fullPath := path.Join(path.Clean(c.Path), folder)
	if err := mkDirIfNotExists(fullPath); err != nil {
		return nil
	}
	storPath := path.Join(fullPath, c.Host) + ".bdb"
	b := badgerStorage{
		path:  storPath,
		host:  c.Host,
		m:     sync.Mutex{},
		logFn: emptyLogFn,
		errFn: emptyLogFn,
	}
	if c.ErrFn != nil {
		b.errFn = c.ErrFn
	}
	if c.LogFn != nil {
		b.logFn = c.LogFn
	}
	return &b
}

// Open opens the badger database if possible.
func (s *badgerStorage) Open() error {
	var err error
	s.m.Lock()
	c := badger.DefaultOptions(s.path).WithLogger(logger{
		logFn: s.logFn,
		errFn: s.errFn,
	})
	s.d, err = badger.Open(c)
	if err != nil {
		err = errors.Annotatef(err, "unable to open storage")
	}
	return err
}

// Close closes the badger database if possible.
func (s *badgerStorage) Close() {
	if s.d == nil {
		return
	}
	s.d.Close()
	s.m.Unlock()
}

// Clone
func (s *badgerStorage) Clone() osin.Storage {
	s.Close()
	return s
}

func itemPath(pieces ...string) []byte {
	return []byte(path.Join(pieces...))
}

func clientPath(id string) []byte {
	return itemPath(clientsBucket, id)
}

func loadTxnClient(c *osin.DefaultClient, id string) func(tx *badger.Txn) error {
	fullPath := clientPath(id)
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
func (s *badgerStorage) GetClient(id string) (osin.Client, error) {
	if err := s.Open(); err != nil {
		return nil, err
	}
	defer s.Close()
	c := new(osin.DefaultClient)
	if err := s.d.View(loadTxnClient(c, id)); err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *badgerStorage) UpdateClient(c osin.Client) error {
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
		return tx.Set(clientPath(c.GetId()), raw)
	})
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *badgerStorage) CreateClient(c osin.Client) error {
	return s.UpdateClient(c)
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *badgerStorage) RemoveClient(id string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(clientPath(id))
	})
}

func authorizePath(code string) []byte {
	return itemPath(authorizeBucket, code)
}

// SaveAuthorize
func (s *badgerStorage) SaveAuthorize(data *osin.AuthorizeData) error {
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
		return tx.Set(authorizePath(data.Code), raw)
	})
}

func loadTxnAuthorize(a *osin.AuthorizeData, code string) func(tx *badger.Txn) error {
	fullPath := authorizePath(code)
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
		a.Client = &osin.DefaultClient{Id: auth.Code}
		if a.ExpireAt().Before(time.Now().UTC()) {
			return errors.Errorf("Token expired at %s.", a.ExpireAt().String())
		}
		return nil
	}
}

// LoadAuthorize
func (s *badgerStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	data := osin.AuthorizeData{}
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	err = s.d.View(loadTxnAuthorize(&data, code))
	if err != nil {
		return nil, err
	}
	client := new(osin.DefaultClient)
	if err = s.d.View(loadTxnClient(client, data.Client.GetId())); err == nil {
		data.Client = client
	}
	return &data, err
}

// RemoveAuthorize
func (s *badgerStorage) RemoveAuthorize(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(authorizePath(code))
	})
}

func accessPath(code string) []byte {
	return itemPath(accessBucket, code)
}

// SaveAccess
func (s *badgerStorage) SaveAccess(data *osin.AccessData) error {
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
			if err := saveRefresh(tx, data.RefreshToken, data.AccessToken); err != nil {
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
		return tx.Set(authorizePath(acc.AccessToken), raw)
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

func loadTxnAccess(a *osin.AccessData, token string) func(tx *badger.Txn) error {
	fullPath := accessPath(token)
	return func(tx *badger.Txn) error {
		it, err := tx.Get(fullPath)
		if err != nil {
			return errors.NewNotFound(err, "Invalid path %s", fullPath)
		}
		return it.Value(loadRawAccess(a))
	}
}

// LoadAccess
func (s *badgerStorage) LoadAccess(code string) (*osin.AccessData, error) {
	err := s.Open()
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()

	result := new(osin.AccessData)
	err = s.d.View(loadTxnAccess(result, code))

	clientId :=  result.Client.GetId()
	if len(clientId) > 0 {
		client := new(osin.DefaultClient)
		if err = s.d.View(loadTxnClient(client, result.Client.GetId())); err == nil {
			result.Client = client
		}
	}
	if len(result.AuthorizeData.Code) > 0 {
		auth := new(osin.AuthorizeData)
		if err = s.d.View(loadTxnAuthorize(auth, result.AuthorizeData.Code)); err == nil {
			result.AuthorizeData = auth
		}
	}
	if result.AccessData != nil && len(result.AccessData.AccessToken) > 0 {
		prev := new(osin.AccessData)
		if err = s.d.View(loadTxnAccess(prev, result.AuthorizeData.Code)); err == nil {
			result.AccessData = prev
		}
	}

	return result, err
}

// RemoveAccess
func (s *badgerStorage) RemoveAccess(token string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(accessPath(token))
	})
}

func refreshPath(refresh string) []byte {
	return itemPath(refreshBucket, refresh)
}

// LoadRefresh
func (s *badgerStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *badgerStorage) RemoveRefresh(token string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open badger store")
	}
	defer s.Close()
	return s.d.Update(func(tx *badger.Txn) error {
		return tx.Delete(refreshPath(token))
	})
}

func saveRefresh(txn *badger.Txn, refresh, access string) (err error) {
	ref := ref{
		Access: access,
	}
	raw, err := json.Marshal(ref)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal refresh token object")
	}
	return txn.Set(refreshPath(refresh), raw)
}
