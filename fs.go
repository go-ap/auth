package auth

import (
	"encoding/json"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"os"
	"path"
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

func mkDirIfNotExists(p string) error {
	if fi, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(p, os.ModeDir|os.ModePerm|0700); err != nil {
				return err
			}
		}
	} else if !fi.IsDir() {
		return errors.Errorf("path exists, and is not a folder %s", p)
	}
	return nil
}

func isStorageCollectionKey(p string) bool {
	base := path.Base(p)
	return base == clientsBucket || base == authorizeBucket || base == accessBucket || base == refreshBucket
}

const (
	objectKey = "__raw.json"
)

func getObjectKey(p string) string {
	return path.Join(p, objectKey)
}

func loadRawFromPath(itPath string) ([]byte, error) {
	f, err := os.Open(itPath)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable find path %s", itPath)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, errors.Annotatef(err, "Unable stat file at path %s", itPath)
	}
	raw := make([]byte, fi.Size())
	cnt, err := f.Read(raw)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable read file at path %s", itPath)
	}
	if cnt != len(raw) {
		return nil, errors.Annotatef(err, "Unable read the whole file at path %s", itPath)
	}
	return raw, nil
}

func (s *fsStorage) loadFromPath(itPath string, loaderFn func([]byte) error) (uint, error) {
	var err error
	var cnt uint = 0
	if isStorageCollectionKey(itPath) {
		err = filepath.Walk(itPath, func(p string, info os.FileInfo, err error) error {
			if err != nil && os.IsNotExist(err) {
				return errors.NotFoundf("%s not found", p)
			}

			it, _ := loadRawFromPath(getObjectKey(p))
			if it != nil {
				if err := loaderFn(it); err == nil {
					cnt++
				}
			}
			return nil
		})
	} else {
		var raw []byte
		raw, err = loadRawFromPath(getObjectKey(itPath))
		if err != nil {
			return cnt, errors.NewNotFound(err, "not found")
		}
		if raw != nil {
			if err := loaderFn(raw); err == nil {
				cnt++
			}
		}
	}
	return cnt, err
}

// NewFSDBStore returns a new postgres storage instance.
func NewFSDBStore(c FSConfig) *fsStorage {
	p, _ := getAbsStoragePath(c.Path)
	if err := mkDirIfNotExists(path.Clean(p)); err != nil {
		return nil
	}
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
func (s *fsStorage) Close() {}

// Open
func (s *fsStorage) Open() error {
	return nil
}

// ListClients
func (s *fsStorage) ListClients() ([]osin.Client, error) {
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	clients := make([]osin.Client, 0)

	_, err = s.loadFromPath(path.Join(s.path, clientsBucket), func(raw []byte) error {
		cl := cl{}
		err := json.Unmarshal(raw, &cl)
		if err != nil {
			return err
		}
		d := osin.DefaultClient{
			Id:          cl.Id,
			Secret:      cl.Secret,
			RedirectUri: cl.RedirectUri,
			UserData:    cl.Extra,
		}
		clients = append(clients, &d)
		return nil
	})

	return clients, err
}

// GetClient
func (s *fsStorage) GetClient(id string) (osin.Client, error) {
	c := osin.DefaultClient{}
	err := s.Open()
	if err != nil {
		return &c, err
	}
	defer s.Close()
	clientPath := path.Join(s.path, clientsBucket, id)
	_, err = s.loadFromPath(clientPath, func(raw []byte) error {
		cl := cl{}
		if err := json.Unmarshal(raw, &cl); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal client object")
		}
		c.Id = cl.Id
		c.Secret = cl.Secret
		c.RedirectUri = cl.RedirectUri
		c.UserData = cl.Extra
		return nil
	})

	return &c, err
}

func createFolderIfNotExists(p string) error {
	if _, err := os.Open(p); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(p, os.ModeDir|os.ModePerm|0770); err != nil {
			return err
		}
	}
	return nil
}

func putItem(basePath string, it interface{}) error {
	raw, err := json.Marshal(it)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal %T", it)
	}
	return putRaw(basePath, raw)
}

func putRaw(basePath string, raw []byte) error {
	filePath := getObjectKey(basePath)
	f, err := os.Open(filePath)
	if err != nil && os.IsNotExist(err){
		f, err = os.Create(filePath)
	}
	if err != nil {
		return errors.Annotatef(err, "Unable to save data to path %s", filePath)
	}
	defer f.Close()
	n, err := f.Write(raw)
	if n != len(raw) {
		return errors.Newf("Unable to save all data to path %s, only saved %d bytes", filePath, n)
	}
	return err
}

// UpdateClient
func (s *fsStorage) UpdateClient(c osin.Client) error {
	if interfaceIsNil(c) {
		return nil
	}
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	if err != nil {
		s.errFn(logrus.Fields{"id": c.GetId()}, err.Error())
		return errors.Annotatef(err, "Invalid user-data")
	}
	cl := cl{
		Id:          c.GetId(),
		Secret:      c.GetSecret(),
		RedirectUri: c.GetRedirectUri(),
		Extra:       c.GetUserData(),
	}
	clientPath := path.Join(s.path, clientsBucket, cl.Id)
	if err = createFolderIfNotExists(clientPath); err != nil {
		return errors.Annotatef(err, "Invalid path %s", clientPath)
	}
	return putItem(clientPath, cl)
}

// CreateClient
func (s *fsStorage) CreateClient(c osin.Client) error {
	return s.UpdateClient(c)
}

// RemoveClient
func (s *fsStorage) RemoveClient(id string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, clientsBucket, id))
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
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, authorizeBucket, code))
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
func (s *fsStorage) RemoveAccess(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, accessBucket, code))
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *fsStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *fsStorage) RemoveRefresh(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, refreshBucket, code))
}
