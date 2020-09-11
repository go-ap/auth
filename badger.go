package auth

import (
	"encoding/json"
	"github.com/dgraph-io/badger"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
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

// SaveAuthorize
func (s *badgerStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	return nil
}

func authorizePath(id string) []byte {
	return itemPath(authorizeBucket, id)
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
	return nil
}

// SaveAccess
func (s *badgerStorage) SaveAccess(data *osin.AccessData) error {
	return nil
}

// LoadAccess
func (s *badgerStorage) LoadAccess(token string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveAccess
func (s *badgerStorage) RemoveAccess(token string) error {
	return nil
}

// LoadRefresh
func (s *badgerStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *badgerStorage) RemoveRefresh(token string) error {
	return nil
}
