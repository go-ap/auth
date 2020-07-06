package auth

import (
	"bytes"
	"encoding/json"
	"github.com/boltdb/bolt"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"time"
)

// boltStorage implements interface "github.com/RangelReale/osin".boltStorage and interface "github.com/ory/osin-storage".boltStorage
type boltStorage struct {
	d     *bolt.DB
	path  string
	root  []byte
	logFn loggerFn
	errFn loggerFn
}

type BoltConfig struct {
	Path       string
	BucketName string
	LogFn      loggerFn
	ErrFn      loggerFn
}

func BootstrapBoltDB(path string, rootBucket []byte) error {
	var err error
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return errors.Annotatef(err, "could not open db")
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(rootBucket)
		if err != nil {
			return errors.Annotatef(err, "could not create root bucket")
		}
		_, err = root.CreateBucketIfNotExists([]byte(accessBucket))
		if err != nil {
			return errors.Annotatef(err, "could not create %s bucket", accessBucket)
		}
		_, err = root.CreateBucketIfNotExists([]byte(refreshBucket))
		if err != nil {
			return errors.Annotatef(err, "could not create %s bucket", refreshBucket)
		}
		_, err = root.CreateBucketIfNotExists([]byte(authorizeBucket))
		if err != nil {
			return errors.Annotatef(err, "could not create %s bucket", authorizeBucket)
		}
		_, err = root.CreateBucketIfNotExists([]byte(clientsBucket))
		if err != nil {
			return errors.Annotatef(err, "could not create %s bucket", clientsBucket)
		}
		return nil
	})
}

// New returns a new postgres storage instance.
func NewBoltDBStore(c BoltConfig) *boltStorage {
	return &boltStorage{
		path:  c.Path,
		root:  []byte(c.BucketName),
		logFn: c.LogFn,
		errFn: c.ErrFn,
	}
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *boltStorage) Clone() osin.Storage {
	s.Close()
	return s
}

// Close the resources the boltStorage potentially holds (using Clone for example)
func (s *boltStorage) Close() {
	if s.d == nil {
		return
	}
	s.d.Close()
}

func (s *boltStorage) Open() error {
	var err error
	s.d, err = bolt.Open(s.path, 0600, nil)
	if err != nil {
		return errors.Annotatef(err, "could not open db")
	}
	return nil
}

func (s *boltStorage) ListClients() ([]osin.Client, error) {
	err := s.Open()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	clients := make([]osin.Client, 0)
	err = s.d.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cl := cl{}
		cb := rb.Bucket([]byte(clientsBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, clientsBucket)
		}
		c := cb.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			if err := json.Unmarshal(raw, &cl); err != nil {
				s.errFn(nil, "Unable to unmarshal client object %s", err)
				continue
			}
			d := osin.DefaultClient{
				Id:          cl.Id,
				Secret:      cl.Secret,
				RedirectUri: cl.RedirectUri,
				UserData:    cl.Extra,
			}
			clients = append(clients, &d)
		}
		return nil
	})
	return clients, err
}

const clientsBucket = "clients"

// GetClient loads the client by id
func (s *boltStorage) GetClient(id string) (osin.Client, error) {
	c := osin.DefaultClient{}
	err := s.Open()
	if err != nil {
		return &c, err
	}
	defer s.Close()
	err = s.d.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cl := cl{}
		cb := rb.Bucket([]byte(clientsBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, clientsBucket)
		}
		raw := cb.Get([]byte(id))
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

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *boltStorage) UpdateClient(c osin.Client) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
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
	raw, err := json.Marshal(cl)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal client object")
	}
	return s.d.Update(func(tx *bolt.Tx) error {
		rb, err := tx.CreateBucketIfNotExists(s.root)
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s", s.root)
		}
		cb, err := rb.CreateBucketIfNotExists([]byte(clientsBucket))
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s/%s", s.root, clientsBucket)
		}
		return cb.Put([]byte(cl.Id), raw)
	})
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *boltStorage) CreateClient(c osin.Client) error {
	return s.UpdateClient(c)
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *boltStorage) RemoveClient(id string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()
	return s.d.Update(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cb := rb.Bucket([]byte(clientsBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, clientsBucket)
		}
		return cb.Delete([]byte(id))
	})
}

const authorizeBucket = "authorize"

// SaveAuthorize saves authorize data.
func (s *boltStorage) SaveAuthorize(data *osin.AuthorizeData) error {
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
	return s.d.Update(func(tx *bolt.Tx) error {
		rb, err := tx.CreateBucketIfNotExists(s.root)
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s", s.root)
		}
		cb, err := rb.CreateBucketIfNotExists([]byte(authorizeBucket))
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s/%s", s.root, authorizeBucket)
		}
		return cb.Put([]byte(data.Code), raw)
	})
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *boltStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	var data osin.AuthorizeData
	err := s.Open()
	if err != nil {
		return &data, err
	}
	defer s.Close()

	auth := auth{}
	err = s.d.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		ab := rb.Bucket([]byte(authorizeBucket))
		if ab == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, authorizeBucket)
		}
		raw := ab.Get([]byte(code))

		if err := json.Unmarshal(raw, &auth); err != nil {
			err := errors.Annotatef(err, "Unable to unmarshal authorization object")
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return err
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
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return err
		}

		c := osin.DefaultClient{}
		cl := cl{}
		cb := rb.Bucket([]byte(clientsBucket))
		if cb != nil {
			rawC := cb.Get([]byte(auth.Client))
			if err := json.Unmarshal(rawC, &cl); err != nil {
				err := errors.Annotatef(err, "Unable to unmarshal client object")
				s.errFn(logrus.Fields{"code": code}, err.Error())
				return nil
			}
			c.Id = cl.Id
			c.Secret = cl.Secret
			c.RedirectUri = cl.RedirectUri
			c.UserData = cl.Extra

			data.Client = &c
		} else {
			err := errors.Newf("Invalid bucket %s/%s", s.root, clientsBucket)
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil
		}
		return nil
	})

	return &data, err
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *boltStorage) RemoveAuthorize(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()

	return s.d.Update(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cb := rb.Bucket([]byte(authorizeBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, authorizeBucket)
		}
		return cb.Delete([]byte(code))
	})
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *boltStorage) SaveAccess(data *osin.AccessData) error {
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
		if err := s.saveRefresh(data.RefreshToken, data.AccessToken); err != nil {
			s.errFn(logrus.Fields{"id": data.Client.GetId()}, err.Error())
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
	raw, err := json.Marshal(acc)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal access object")
	}
	return s.d.Update(func(tx *bolt.Tx) error {
		rb, err := tx.CreateBucketIfNotExists(s.root)
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s", s.root)
		}
		cb, err := rb.CreateBucketIfNotExists([]byte(accessBucket))
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s/%s", s.root, accessBucket)
		}
		return cb.Put([]byte(acc.AccessToken), raw)
	})
}

const accessBucket = "access"

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *boltStorage) LoadAccess(code string) (*osin.AccessData, error) {
	var result osin.AccessData
	err := s.Open()
	if err != nil {
		return &result, errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()

	err = s.d.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		var access acc
		ab := rb.Bucket([]byte(accessBucket))
		if ab == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, accessBucket)
		}
		raw := ab.Get([]byte(code))
		if raw == nil {
			return errors.Newf("Unable to load authorize information for %s/%s/%s", s.root, accessBucket, code)
		}
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

		c := osin.DefaultClient{}
		cl := cl{}
		cb := rb.Bucket([]byte(clientsBucket))
		if cb == nil {
			err := errors.Newf("Invalid bucket %s/%s", s.root, clientsBucket)
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil
		}
		rawC := cb.Get([]byte(access.Client))
		if err := json.Unmarshal(rawC, &cl); err != nil {
			err := errors.Annotatef(err, "Unable to unmarshal client object")
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil
		}
		c.Id = cl.Id
		c.Secret = cl.Secret
		c.RedirectUri = cl.RedirectUri
		c.UserData = cl.Extra

		result.Client = &c
		if err != nil {
			err := errors.Annotatef(err, "Unable to load client for current access token")
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil
		}

		authB := rb.Bucket([]byte(authorizeBucket))
		if authB == nil {
			err := errors.Newf("Invalid bucket %s/%s", s.root, authorizeBucket)
			s.errFn(logrus.Fields{"code": code}, err.Error())
			return nil
		}
		if access.Authorize != "" {
			auth := auth{}

			rawAuth := authB.Get([]byte(access.Authorize))
			if rawAuth == nil {
				//err := errors.Newf("Invalid authorize data")
				//s.errFn(logrus.Fields{"code": code}, err.Error())
				return nil
			}
			if err := json.Unmarshal(rawAuth, &auth); err != nil {
				//err := errors.Annotatef(err, "Unable to unmarshal authorization object")
				//s.errFn(logrus.Fields{"code": code}, err.Error())
				return nil
			}

			data := osin.AuthorizeData{
				Code:        auth.Code,
				ExpiresIn:   int32(auth.ExpiresIn),
				Scope:       auth.Scope,
				RedirectUri: auth.RedirectURI,
				State:       auth.State,
				CreatedAt:   auth.CreatedAt,
				UserData:    auth.Extra,
			}

			if data.ExpireAt().Before(time.Now().UTC()) {
				err := errors.Errorf("Token expired at %s.", data.ExpireAt().String())
				s.errFn(logrus.Fields{"code": code}, err.Error())
				return nil
			}
			result.AuthorizeData = &data
		}
		if access.Previous != "" {
			var prevAccess acc
			rawPrev := ab.Get([]byte(access.Previous))
			if err := json.Unmarshal(rawPrev, &prevAccess); err != nil {
				err := errors.Annotatef(err, "Unable to unmarshal previous access object")
				s.errFn(logrus.Fields{"code": code}, err.Error())
				return nil
			}
			prev := osin.AccessData{}
			prev.AccessToken = prevAccess.AccessToken
			prev.RefreshToken = prevAccess.RefreshToken
			prev.ExpiresIn = int32(prevAccess.ExpiresIn)
			prev.Scope = prevAccess.Scope
			prev.RedirectUri = prevAccess.RedirectURI
			prev.CreatedAt = prevAccess.CreatedAt.UTC()
			prev.UserData = prevAccess.Extra

			result.AccessData = &prev
		}
		return nil
	})

	return &result, err
}

// RemoveAccess revokes or deletes an AccessData.
func (s *boltStorage) RemoveAccess(code string) (err error) {
	return s.d.Update(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cb := rb.Bucket([]byte(accessBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, accessBucket)
		}
		return cb.Delete([]byte(code))
	})
}

const refreshBucket = "refresh"

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *boltStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	err := s.Open()
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()
	var ref ref
	err = s.d.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cb := rb.Bucket([]byte(refreshBucket))
		prefix := []byte(code)
		u := cb.Cursor()
		if u == nil {
			return errors.Errorf("Invalid bucket cursor %s/%s", s.root, refreshBucket)
		}
		for k, v := u.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = u.Next() {
			if err := json.Unmarshal(v, &ref); err != nil {
				return errors.Annotatef(err, "Unable to unmarshal refresh token object")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.LoadAccess(ref.Access)
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *boltStorage) RemoveRefresh(code string) error {
	err := s.Open()
	if err != nil {
		return errors.Annotatef(err, "Unable to open boldtb")
	}
	defer s.Close()
	return s.d.Update(func(tx *bolt.Tx) error {
		rb := tx.Bucket(s.root)
		if rb == nil {
			return errors.Errorf("Invalid bucket %s", s.root)
		}
		cb := rb.Bucket([]byte(refreshBucket))
		if cb == nil {
			return errors.Newf("Invalid bucket %s/%s", s.root, refreshBucket)
		}
		return cb.Delete([]byte(code))
	})
}

func (s *boltStorage) saveRefresh(refresh, access string) (err error) {
	ref := ref{
		Access: access,
	}
	raw, err := json.Marshal(ref)
	if err != nil {
		return errors.Annotatef(err, "Unable to marshal refresh token object")
	}
	return s.d.Update(func(tx *bolt.Tx) error {
		rb, err := tx.CreateBucketIfNotExists(s.root)
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s", s.root)
		}
		cb, err := rb.CreateBucketIfNotExists([]byte(refreshBucket))
		if err != nil {
			return errors.Annotatef(err, "Invalid bucket %s/%s", s.root, refreshBucket)
		}
		return cb.Put([]byte(refresh), raw)
	})
}
