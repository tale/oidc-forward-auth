package store

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/oklog/ulid/v2"
)

// The key that a state ID maps to in the state store.
type StateKey struct {
	Nonce          string
	RedirectURL    string
	AuthInProgress bool
}

var stateStore *lru.Cache[ulid.ULID, StateKey]

// Initialize the state store with a given size.
func InitStateStore(size int) error {
	var err error
	stateStore, err = lru.New[ulid.ULID, StateKey](size)
	if err != nil {
		return fmt.Errorf("failed to initialize state store: %w", err)
	}

	return nil
}

func SetState(nonce, redirectURL string) (*ulid.ULID, error) {
	if stateStore == nil {
		return nil, fmt.Errorf("state store is not initialized")
	}

	id := ulid.Make()

	key := StateKey{
		Nonce:          nonce,
		RedirectURL:    redirectURL,
		AuthInProgress: true,
	}

	stateStore.Add(id, key)
	return &id, nil
}

func GetState(id ulid.ULID) (*StateKey, error) {
	if stateStore == nil {
		return nil, fmt.Errorf("state store is not initialized")
	}

	value, ok := stateStore.Get(id)
	if !ok {
		return nil, fmt.Errorf("state not found for id: %s", id)
	}

	return &value, nil
}

func DeleteState(id *ulid.ULID) error {
	if stateStore == nil {
		return fmt.Errorf("state store is not initialized")
	}

	if !stateStore.Remove(*id) {
		return fmt.Errorf("failed to delete state for id: %s", *id)
	}

	return nil
}
