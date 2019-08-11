package auth

import (
	"github.com/buger/jsonparser"
	"github.com/go-ap/activitypub"
	"github.com/go-ap/activitystreams"
)

// PublicKey holds the ActivityPub compatible public key data
type PublicKey struct {
	ID           activitystreams.ObjectID     `jsonld:"id,omitempty"`
	Owner        activitystreams.ObjectOrLink `jsonld:"owner,omitempty"`
	PublicKeyPem string                       `jsonld:"publicKeyPem,omitempty"`
}

// Person it should be identical to:
//    github.com/go-ap/activitypub/actors.go#To
// We need it here in order to be able to add to it our Score property
type Person struct {
	activitypub.Person
	PublicKey PublicKey `jsonld:"publicKey,omitempty"`
}

type Service = Person
type Group = Person
type Application = Person

// GetID returns the ObjectID pointer of current Person instance
func (p Person) GetID() *activitystreams.ObjectID {
	id := activitystreams.ObjectID(p.ID)
	return &id
}
func (p Person) GetType() activitystreams.ActivityVocabularyType {
	return activitystreams.ActivityVocabularyType(p.Type)
}
func (p Person) GetLink() activitystreams.IRI {
	return activitystreams.IRI(p.ID)
}
func (p Person) IsLink() bool {
	return false
}

func (p Person) IsObject() bool {
	return true
}

func (p *PublicKey) UnmarshalJSON(data []byte) error {
	if id, err := jsonparser.GetString(data, "id"); err == nil {
		p.ID = activitystreams.ObjectID(id)
	} else {
		return err
	}
	if o, err := jsonparser.GetString(data, "owner"); err == nil {
		p.Owner = activitystreams.IRI(o)
	} else {
		return err
	}
	if pub, err := jsonparser.GetString(data, "publicKeyPem"); err == nil {
		p.PublicKeyPem = pub
	} else {
		return err
	}
	return nil
}

// UnmarshalJSON tries to load json data to Person object
func (p *Person) UnmarshalJSON(data []byte) error {
	app := activitypub.Person{}
	if err := app.UnmarshalJSON(data); err != nil {
		return err
	}

	p.Person = app
	if pubData, _, _, err := jsonparser.Get(data, "publicKey"); err == nil {
		p.PublicKey.UnmarshalJSON(pubData)
	}

	return nil
}

// ToPerson
func ToPerson(it activitystreams.Item) (*Person, error) {
	switch o := it.(type) {
	case *Person:
		return o, nil
	case Person:
		return &o, nil
	}
	ob, err := activitypub.ToPerson(it)
	if err != nil {
		ob, err := activitystreams.ToObject(it)
		if err != nil {
			return nil, err
		}
		p := Person{
			Person:    activitypub.Person{
				Parent:            *ob,
			},
		}
		return &p, err
	}
	p := Person{}
	p.Person = *ob
	return &p, nil
}

// ToObject
func ToObject(it activitystreams.Item) (*activitystreams.Object, error) {
	switch o := it.(type) {
	case *Person:
		return &o.Parent, nil
	case Person:
		return &o.Parent, nil
	}
	return activitystreams.ToObject(it)
}
