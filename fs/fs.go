package fs

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"time"

	"github.com/go-ap/auth/internal/log"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

const (
	defaultPerm     = os.ModeDir | os.ModePerm | 0770
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
	path  string
	logFn log.LoggerFn
	errFn log.LoggerFn
}

type Config struct {
	Path  string
	LogFn log.LoggerFn
	ErrFn log.LoggerFn
}

func mkDirIfNotExists(p string) error {
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

func (s *stor) loadFromPath(itPath string, loaderFn func([]byte) error) (uint, error) {
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

// New returns a new filesystem storage instance.
func New(c Config) *stor {
	fullPath := path.Join(path.Clean(c.Path), folder)
	if err := mkDirIfNotExists(fullPath); err != nil {
		return nil
	}
	s := stor{
		path:  fullPath,
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

// Clone
func (s *stor) Clone() osin.Storage {
	return s
}

// Close
func (s *stor) Close() {}

// Open
func (s *stor) Open() error {
	return nil
}

// ListClients
func (s *stor) ListClients() ([]osin.Client, error) {
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

func (s *stor) loadClientFromPath(clientPath string) (osin.Client, error) {
	c := new(osin.DefaultClient)
	_, err := s.loadFromPath(clientPath, func(raw []byte) error {
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
	return c, err
}

// GetClient
func (s *stor) GetClient(id string) (osin.Client, error) {
	if id == "" {
		return nil, errors.NotFoundf("Empty client id")
	}
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.loadClientFromPath(path.Join(s.path, clientsBucket, id))
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
	if err != nil && os.IsNotExist(err) {
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
func (s *stor) UpdateClient(c osin.Client) error {
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
func (s *stor) CreateClient(c osin.Client) error {
	return s.UpdateClient(c)
}

// RemoveClient
func (s *stor) RemoveClient(id string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, clientsBucket, id))
}

// SaveAuthorize saves authorize data.
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
	authorizePath := path.Join(s.path, authorizeBucket, auth.Code)
	if err = createFolderIfNotExists(authorizePath); err != nil {
		return errors.Annotatef(err, "Invalid path %s", authorizePath)
	}
	return putItem(authorizePath, auth)
}

func (s *stor) loadAuthorizeFromPath(authPath string) (*osin.AuthorizeData, error) {
	data := new(osin.AuthorizeData)
	_, err := s.loadFromPath(authPath, func(raw []byte) error {
		auth := auth{}
		if err := json.Unmarshal(raw, &auth); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal client object")
		}
		data.Code = auth.Code
		data.ExpiresIn = int32(auth.ExpiresIn)
		data.Scope = auth.Scope
		data.RedirectUri = auth.RedirectURI
		data.State = auth.State
		data.CreatedAt = auth.CreatedAt
		data.UserData = auth.Extra

		if data.ExpireAt().Before(time.Now().UTC()) {
			err := errors.Errorf("Token expired at %s.", data.ExpireAt().String())
			s.errFn(logrus.Fields{"code": auth.Code}, err.Error())
			return err
		}
		cl, err := s.loadClientFromPath(path.Join(s.path, clientsBucket, auth.Client))
		if err != nil {
			return err
		}
		data.Client = &osin.DefaultClient{
			Id:          cl.GetId(),
			Secret:      cl.GetSecret(),
			RedirectUri: cl.GetRedirectUri(),
			UserData:    cl.GetUserData(),
		}
		return nil
	})
	return data, err
}

// LoadAuthorize looks up AuthorizeData by a code.
func (s *stor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty authorize code")
	}
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.loadAuthorizeFromPath(path.Join(s.path, authorizeBucket, code))
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *stor) RemoveAuthorize(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, authorizeBucket, code))
}

// SaveAccess writes AccessData.
func (s *stor) SaveAccess(data *osin.AccessData) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
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
		ref := ref{
			Access: data.AccessToken,
		}
		refreshPath := path.Join(s.path, refreshBucket, data.RefreshToken)
		if err = createFolderIfNotExists(refreshPath); err != nil {
			return errors.Annotatef(err, "Invalid path %s", refreshPath)
		}
		if err := putItem(refreshPath, ref); err != nil {
			return err
		}
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
	authorizePath := path.Join(s.path, accessBucket, acc.AccessToken)
	if err = createFolderIfNotExists(authorizePath); err != nil {
		return errors.Annotatef(err, "Invalid path %s", authorizePath)
	}
	return putItem(authorizePath, acc)
}

func (s *stor) loadAccessFromPath(accessPath string) (*osin.AccessData, error) {
	result := new(osin.AccessData)
	_, err := s.loadFromPath(accessPath, func(raw []byte) error {
		access := acc{}
		if err := json.Unmarshal(raw, &access); err != nil {
			return errors.Annotatef(err, "Unable to unmarshal access object")
		}
		result.AccessToken = access.AccessToken
		result.RefreshToken = access.RefreshToken
		result.ExpiresIn = int32(access.ExpiresIn)
		result.Scope = access.Scope
		result.RedirectUri = access.RedirectURI
		result.CreatedAt = access.CreatedAt.UTC()
		result.UserData = access.Extra

		if access.Authorize != "" {
			data, err := s.loadAuthorizeFromPath(path.Join(s.path, authorizeBucket, access.Authorize))
			if err != nil {
				err := errors.Annotatef(err, "Unable to load authorize data for current access token %s.", access.AccessToken)
				s.errFn(logrus.Fields{"code": access.AccessToken}, err.Error())
				return nil
			}
			if data.ExpireAt().Before(time.Now().UTC()) {
				err := errors.Errorf("Token expired at %s.", data.ExpireAt().String())
				s.errFn(logrus.Fields{"code": access.AccessToken}, err.Error())
				return nil
			}
			result.AuthorizeData = data
		}
		if access.Previous != "" {
			_, err := s.loadFromPath(accessPath, func(raw []byte) error {
				access := acc{}
				if err := json.Unmarshal(raw, &access); err != nil {
					return errors.Annotatef(err, "Unable to unmarshal access object")
				}
				prev := new(osin.AccessData)
				prev.AccessToken = access.AccessToken
				prev.RefreshToken = access.RefreshToken
				prev.ExpiresIn = int32(access.ExpiresIn)
				prev.Scope = access.Scope
				prev.RedirectUri = access.RedirectURI
				prev.CreatedAt = access.CreatedAt.UTC()
				prev.UserData = access.Extra
				result.AccessData = prev
				return nil
			})
			if err != nil {
				err := errors.Annotatef(err, "Unable to load previous access token for %s.", access.AccessToken)
				s.errFn(logrus.Fields{"code": access.AccessToken}, err.Error())
				return nil
			}
		}
		return nil
	})
	return result, err
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
func (s *stor) LoadAccess(code string) (*osin.AccessData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty access code")
	}
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	return s.loadAccessFromPath(path.Join(s.path, accessBucket, code))
}

// RemoveAccess revokes or deletes an AccessData.
func (s *stor) RemoveAccess(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, accessBucket, code))
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
func (s *stor) LoadRefresh(code string) (*osin.AccessData, error) {
	if code == "" {
		return nil, errors.NotFoundf("Empty refresh code")
	}
	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *stor) RemoveRefresh(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open fs storage")
	}
	defer s.Close()
	return os.RemoveAll(path.Join(s.path, refreshBucket, code))
}
