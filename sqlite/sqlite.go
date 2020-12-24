package sqlite

import (
	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

// NewFSStore returns a new filesystem storage instance.
func NewSqliteStore(c SqliteConfig) *sqliteStorage {
	return new(sqliteStorage)
}

type sqliteStorage struct {
	path  string
	logFn log.LoggerFn
	errFn log.LoggerFn
}

type SqliteConfig struct {
	Path  string
	LogFn log.LoggerFn
	ErrFn log.LoggerFn
}

var errNotImplemented = errors.NotImplementedf("not implemented")

// Clone
func (s *sqliteStorage) Clone() osin.Storage {
	return s
}

// Close
func (s *sqliteStorage) Close() {}

// Open
func (s *sqliteStorage) Open() error {
	return nil
}

// ListClients
func (s *sqliteStorage) ListClients() ([]osin.Client, error) {
	return nil, errNotImplemented
}

// GetClient
func (s *sqliteStorage) GetClient(id string) (osin.Client, error) {
	return nil, errNotImplemented
}

// UpdateClient
func (s *sqliteStorage) UpdateClient(c osin.Client) error {
	return errNotImplemented
}
// CreateClient
func (s *sqliteStorage) CreateClient(c osin.Client) error {
	return errNotImplemented
}

// RemoveClient
func (s *sqliteStorage) RemoveClient(id string) error {
	return errNotImplemented
}

// SaveAuthorize saves authorize data.
func (s *sqliteStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	return errNotImplemented
}

// LoadAuthorize looks up AuthorizeData by a code.
func (s *sqliteStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	return nil, errNotImplemented
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *sqliteStorage) RemoveAuthorize(code string) error {
	return errNotImplemented
}

// SaveAccess writes AccessData.
func (s *sqliteStorage) SaveAccess(data *osin.AccessData) error {
	return errNotImplemented
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *sqliteStorage) LoadAccess(code string) (*osin.AccessData, error) {
	return nil, errNotImplemented
}
// RemoveAccess revokes or deletes an AccessData.
func (s *sqliteStorage) RemoveAccess(code string) error {
	return errNotImplemented
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *sqliteStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, errNotImplemented
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *sqliteStorage) RemoveRefresh(code string) error {
	return errNotImplemented
}
