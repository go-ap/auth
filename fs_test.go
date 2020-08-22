package auth

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"testing"
)

var (
	seedFolder = fmt.Sprintf("test-%d", rand.Int31())
	tempFolder = path.Join(os.TempDir(), seedFolder)
)

func cleanup() {
	os.RemoveAll(tempFolder)
}

func TestFsStorage_Close(t *testing.T) {
	s := fsStorage{}
	s.Close()
}

func TestFsStorage_Open(t *testing.T) {
	s := fsStorage{}
	err := s.Open()
	if err != nil {
		t.Error("Expected nil when opening fsStorage")
	}
}

func TestFsStorage_ListClients(t *testing.T) {
	defer cleanup()

	tmp := path.Join(tempFolder, clientsBucket)
	s := fsStorage{
		path: tempFolder,
	}
	os.MkdirAll(tmp, os.ModeDir|os.ModePerm|0700)
	_, err := s.ListClients()
	if err != nil {
		t.Errorf("Error when loading clients: %s", err)
	}
}
