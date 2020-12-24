package badger

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v2"
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

func cleanup() {
	os.RemoveAll(tempFolder)
}

func initializeStor() *stor {
	os.RemoveAll(tempFolder)
	return New(Config{Path: tempFolder})
}

func saveBadgerClients(s *stor, clients ...cl) error {
	for _, c := range clients {
		if err := saveBadgerClient(s, c); err != nil {
			return err
		}
	}
	return nil
}

func saveBadgerItem(s *stor, it interface{}, basePath string) error {
	raw, err := json.Marshal(it)
	if err != nil {
		return err
	}
	if s.d == nil {
		s.Open()
		defer s.Close()
	}
	return s.d.Update(func(tx *badger.Txn) error {
		if err := tx.Set([]byte(basePath), raw); err != nil {
			return err
		}
		return nil
	})
}

func saveBadgerClient(s *stor, client cl) error {
	if len(client.Id) == 0 {
		return nil
	}
	testClientPath := path.Join(s.host, clientsBucket, client.Id)
	return saveBadgerItem(s, client, testClientPath)
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
				Id:          "test-client-id",
			},
		},
		err: nil,
	},
}

func TestStor_GetClient(t *testing.T) {
	defer cleanup()
	s := initializeStor()

	for name, tt := range loadClientTests {
		if err := saveBadgerClients(s, tt.clients...); err != nil {
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
