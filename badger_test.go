package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger"
	"os"
	"path"
	"reflect"
	"testing"
)

func initializeBadgerStorage() *badgerStorage {
	os.RemoveAll(tempFolder)
	return NewBadgerStore(FSConfig{Path:  tempFolder})
}

func saveBadgerClients(s *badgerStorage, clients ...cl) error {
	for _, c := range clients {
		if err := saveBadgerClient(s, c); err != nil {
			return err
		}
	}
	return nil
}

func saveBadgerItem(s *badgerStorage, it interface{}, basePath string) error {
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

func saveBadgerClient(s *badgerStorage, client cl) error {
	if len(client.Id) == 0 {
		return nil
	}
	testClientPath := path.Join(s.host, clientsBucket, client.Id)
	return saveBadgerItem(s, client, testClientPath)
}

func TestBadgerStorage_GetClient(t *testing.T) {
	defer cleanup()
	s := initializeBadgerStorage()

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