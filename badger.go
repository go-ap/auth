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
	return s
}

// GetClient
func (s *badgerStorage) GetClient(id string) (osin.Client, error) {
	return nil, nil
}

// SaveAuthorize
func (s *badgerStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	return nil
}

// LoadAuthorize
func (s *badgerStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	return nil, nil
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
