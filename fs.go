package auth

import (
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"os"
	"path/filepath"
)

type fsStorage struct {
	path  string
	logFn loggerFn
	errFn loggerFn
}

type FSConfig struct {
	Path  string
	LogFn loggerFn
	ErrFn loggerFn
}

func getAbsStoragePath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		var err error
		p, err = filepath.Abs(p)
		if err != nil {
			return "", err
		}
	}
	if fi, err := os.Stat(p); err != nil {
		return "", err
	} else if !fi.IsDir() {
		return "", errors.NotValidf("path %s is invalid for storage", p)
	}
	return p, nil
}

// NewFSDBStore returns a new postgres storage instance.
func NewFSDBStore(c FSConfig) *fsStorage {
	p, _ := getAbsStoragePath(c.Path)
	return &fsStorage{
		path:  p,
		logFn: c.LogFn,
		errFn: c.ErrFn,
	}
}

// Clone
func (s *fsStorage) Clone() osin.Storage {
	return s
}

// Close
func (s *fsStorage) Close() {
}

// Open
func (s *fsStorage) Open() error {
	if err != nil {
		return err
	}
	return nil
}

// ListClients
func (s *fsStorage) ListClients() ([]osin.Client, error) {
	return nil, nil
}

// GetClietn
func (s *fsStorage) GetClient(id string) (osin.Client, error) {
	return nil, nil
}

// UpdateClient
func (s *fsStorage) UpdateClient(c osin.Client) error {
	return nil
}

// CreateClient
func (s *fsStorage) CreateClient(c osin.Client) error {
	return nil
}

// RemoveClient
func (s *fsStorage) RemoveClient(id string) error {
	return nil
}

// SaveAuthorize saves authorize data.
func (s *fsStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
func (s *fsStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	return nil, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *fsStorage) RemoveAuthorize(code string) error {
	return nil
}

// SaveAccess writes AccessData.
func (s *fsStorage) SaveAccess(data *osin.AccessData) error {
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *fsStorage) LoadAccess(code string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *fsStorage) RemoveAccess(code string) (err error) {
	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *fsStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *fsStorage) RemoveRefresh(code string) error {
	return nil
}
