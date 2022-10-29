package fs

import (
	"encoding/json"
	"errors"
	"fmt"
	auth2 "github.com/go-ap/auth"
	"github.com/openshift/osin"
	"math/rand"
	"os"
	"path"
	"reflect"
	"testing"
)

var (
	seedFolder = fmt.Sprintf("test-%d", rand.Int())
	tempFolder = path.Join(os.TempDir(), seedFolder)
)

func saveFsClients(base string, clients ...cl) error {
	for _, c := range clients {
		if err := saveFsClient(c, base); err != nil {
			return err
		}
	}
	return nil
}

func saveFsItem(it interface{}, basePath string) error {
	if err := os.MkdirAll(basePath, defaultPerm); err != nil {
		return err
	}

	clientFile := getObjectKey(basePath)
	f, err := os.Create(clientFile)
	if err != nil {
		return err
	}
	defer f.Close()

	var raw []byte
	raw, err = json.Marshal(it)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err != nil {
		return err
	}
	return nil
}

func saveFsClient(client cl, basePath string) error {
	if len(client.Id) == 0 {
		return nil
	}
	testClientPath := path.Join(basePath, clientsBucket, client.Id)
	return saveFsItem(client, testClientPath)
}

func initialize() *stor {
	os.RemoveAll(tempFolder)

	os.MkdirAll(path.Join(tempFolder, clientsBucket), defaultPerm)
	os.MkdirAll(path.Join(tempFolder, accessBucket), defaultPerm)
	os.MkdirAll(path.Join(tempFolder, authorizeBucket), defaultPerm)
	os.MkdirAll(path.Join(tempFolder, refreshBucket), defaultPerm)
	s := stor{path: tempFolder, logFn: auth2.EmptyLogFn, errFn: auth2.EmptyLogFn}
	return &s
}

func cleanup() {
	os.RemoveAll(tempFolder)
}

func TestStor_Close(t *testing.T) {
	s := stor{}
	s.Close()
}

func TestStor_Open(t *testing.T) {
	s := stor{}
	err := s.Open()
	if err != nil {
		t.Errorf("Expected nil when opening %T", s)
	}
}

var loadClientTests = map[string]struct {
	clients []cl
	want    []osin.Client
	err     error
}{
	"nil": {
		clients: []cl{},
		want:    []osin.Client{},
		err:     nil,
	},
	"test-client-id": {
		clients: []cl{
			{
				Id: "test-client-id",
			},
		},
		want: []osin.Client{
			&osin.DefaultClient{
				Id: "test-client-id",
			},
		},
		err: nil,
	},
}

func TestStor_ListClients(t *testing.T) {

	for name, tt := range loadClientTests {
		s := initialize()
		if err := saveFsClients(s.path, tt.clients...); err != nil {
			t.Logf("Unable to save clients: %s", err)
			cleanup()
			continue
		}
		t.Run(name, func(t *testing.T) {
			clients, err := s.ListClients()
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Errorf("Error when loading clients, expected %s, received %s", tt.err, err)
			}
			if tt.err == nil && err != nil {
				t.Errorf("Unexpected error when loading clients, received %s", err)
			}
			if len(clients) != len(tt.want) {
				t.Errorf("Error when loading clients, expected %d items, received %d", len(tt.want), len(clients))
			}
			if !reflect.DeepEqual(clients, tt.want) {
				t.Errorf("Error when loading clients, expected %#v, received %#v", tt.want, clients)
			}
		})
		cleanup()
	}
}

func TestStor_Clone(t *testing.T) {
	s := new(stor)
	ss := s.Clone()
	s1, ok := ss.(*stor)
	if !ok {
		t.Errorf("Error when cloning storage, unable to convert interface back to %T: %T", s, ss)
	}
	if !reflect.DeepEqual(s, s1) {
		t.Errorf("Error when cloning storage, invalid pointer returned %p: %p", s, s1)
	}
}

func TestStor_GetClient(t *testing.T) {
	defer cleanup()
	s := initialize()

	for name, tt := range loadClientTests {
		if err := saveFsClients(s.path, tt.clients...); err != nil {
			t.Logf("Unable to save clients: %s", err)
			continue
		}
		for i, cl := range tt.clients {
			name = fmt.Sprintf("%s:%d", name, i)
			t.Run(name, func(t *testing.T) {
				client, err := s.GetClient(cl.Id)
				if tt.err != nil && !errors.Is(err, tt.err) {
					t.Errorf("Error when loading clients, expected %s, received %s", tt.err, err)
				}
				if tt.err == nil && err != nil {
					t.Errorf("Unexpected error when loading clients, received %s", err)
				}
				expected := tt.want[i]
				if !reflect.DeepEqual(client, expected) {
					t.Errorf("Error when loading clients, expected %#v, received %#v", expected, client)
				}
			})
		}
	}
}

var createClientTests = map[string]struct {
	client *osin.DefaultClient
	err    error
}{
	"nil": {
		nil,
		nil,
	},
	"test-client": {
		&osin.DefaultClient{
			Id:          "test-client",
			Secret:      "asd",
			RedirectUri: "https://example.com",
			UserData:    nil,
		},
		nil,
	},
}

func TestStor_CreateClient(t *testing.T) {
	defer cleanup()
	s := initialize()

	for name, tt := range createClientTests {
		t.Run(name, func(t *testing.T) {
			err := s.CreateClient(tt.client)
			if tt.err != nil && err == nil {
				t.Errorf("Unexpected error when calling CreateClient, received %s", err)
			}
			if tt.client == nil {
				return
			}
			filePath := getObjectKey(path.Join(s.path, clientsBucket, tt.client.Id))
			f, err := os.Open(filePath)
			if err != nil {
				t.Errorf("Unable to read %s client file: %s", filePath, err)
			}
			defer f.Close()

			fi, _ := f.Stat()
			raw := make([]byte, fi.Size())
			_, err = f.Read(raw)
			if err != nil {
				t.Errorf("Unable to read %s client raw data: %s", filePath, err)
			}
			l := new(osin.DefaultClient)
			err = json.Unmarshal(raw, l)
			if err != nil {
				t.Errorf("Unable to unmarshal %s client raw data: %s", filePath, err)
			}
			if !reflect.DeepEqual(l, tt.client) {
				t.Errorf("Error when saving client, expected %#v, received %#v", tt.client, l)
			}
		})
	}
}

func TestStor_UpdateClient(t *testing.T) {
	defer cleanup()
	s := initialize()

	for name, tt := range createClientTests {
		t.Run(name, func(t *testing.T) {
			err := s.CreateClient(tt.client)
			if tt.err != nil && err == nil {
				t.Errorf("Unexpected error when calling CreateClient, received %s", err)
			}
			if tt.client == nil {
				return
			}
			filePath := getObjectKey(path.Join(s.path, clientsBucket, tt.client.Id))
			f, err := os.Open(filePath)
			if err != nil {
				t.Errorf("Unable to read %s client file: %s", filePath, err)
			}
			defer f.Close()

			fi, _ := f.Stat()
			raw := make([]byte, fi.Size())
			_, err = f.Read(raw)
			if err != nil {
				t.Errorf("Unable to read %s client raw data: %s", filePath, err)
			}
			l := new(osin.DefaultClient)
			err = json.Unmarshal(raw, l)
			if err != nil {
				t.Errorf("Unable to unmarshal %s client raw data: %s", filePath, err)
			}
			if !reflect.DeepEqual(l, tt.client) {
				t.Errorf("Error when saving client, expected %#v, received %#v", tt.client, l)
			}
		})
	}
}

func TestStor_LoadAuthorize(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_LoadAccess(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_LoadRefresh(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_RemoveAccess(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_RemoveAuthorize(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_RemoveClient(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_RemoveRefresh(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_SaveAccess(t *testing.T) {
	t.Skipf("TODO")
}

func TestStor_SaveAuthorize(t *testing.T) {
	t.Skipf("TODO")
}

func TestNewFSDBStoreStore(t *testing.T) {
	t.Skipf("TODO")
}
