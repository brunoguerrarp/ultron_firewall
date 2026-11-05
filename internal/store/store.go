// Package store provides durable storage (rules, history, config and the
// master-password hash) backed by a single bbolt file. bbolt is pure Go, so
// the application needs no cgo/SQLite.
package store

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"ultron_firewall/internal/model"
)

var (
	bucketMeta    = []byte("meta")
	bucketRules   = []byte("rules")
	bucketHistory = []byte("history")

	keyConfig = []byte("config")
	keyAuth   = []byte("auth")
)

// Store is the persistence layer.
type Store struct {
	db  *bolt.DB
	mu  sync.RWMutex
	cfg model.Config
}

// Open opens (or creates) the database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	s := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketRules, bucketHistory} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		// Seed default config on first run.
		raw := tx.Bucket(bucketMeta).Get(keyConfig)
		if raw == nil {
			s.cfg = model.DefaultConfig()
			buf, _ := json.Marshal(s.cfg)
			return tx.Bucket(bucketMeta).Put(keyConfig, buf)
		}
		return json.Unmarshal(raw, &s.cfg)
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Config returns the current configuration.
func (s *Store) Config() model.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// SetConfig persists the configuration.
func (s *Store) SetConfig(cfg model.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyConfig, buf)
	}); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

// ---- Auth (master password hash) ----

// HasAuth reports whether a master password has been set.
func (s *Store) HasAuth() bool {
	var has bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		has = tx.Bucket(bucketMeta).Get(keyAuth) != nil
		return nil
	})
	return has
}

// AuthHash returns the stored bcrypt hash (nil if unset).
func (s *Store) AuthHash() []byte {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get(keyAuth)
		if v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out
}

// SetAuthHash stores the bcrypt hash of the master password.
func (s *Store) SetAuthHash(hash []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyAuth, hash)
	})
}

// ---- Rules ----

// ListRules returns all rules.
func (s *Store) ListRules() ([]model.Rule, error) {
	var rules []model.Rule
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRules).ForEach(func(_, v []byte) error {
			var r model.Rule
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			rules = append(rules, r)
			return nil
		})
	})
	return rules, err
}

// PutRule inserts or updates a rule.
func (s *Store) PutRule(r model.Rule) error {
	buf, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRules).Put([]byte(r.ID), buf)
	})
}

// DeleteRule removes a rule by id.
func (s *Store) DeleteRule(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRules).Delete([]byte(id))
	})
}

// ---- History ----

// AppendHistory stores a decision record.
func (s *Store) AppendHistory(e model.HistoryEntry) error {
	buf, err := json.Marshal(e)
	if err != nil {
		return err
	}
	key := []byte(fmt.Sprintf("%020d-%s", e.Time.UnixNano(), e.ID))
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHistory).Put(key, buf)
	})
}

// ListHistory returns up to limit entries, newest first.
func (s *Store) ListHistory(limit int) ([]model.HistoryEntry, error) {
	if limit <= 0 {
		limit = 500
	}
	var out []model.HistoryEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketHistory).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var e model.HistoryEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// ClearHistory removes all history entries.
func (s *Store) ClearHistory() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(bucketHistory); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketHistory)
		return err
	})
}

// PruneHistory keeps only the newest keep entries.
func (s *Store) PruneHistory(keep int) error {
	if keep <= 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistory)
		total := b.Stats().KeyN
		if total <= keep {
			return nil
		}
		toDelete := total - keep
		c := b.Cursor()
		n := 0
		for k, _ := c.First(); k != nil && n < toDelete; k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
			n++
		}
		return nil
	})
}
