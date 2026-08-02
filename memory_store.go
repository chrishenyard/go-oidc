package auth

import (
	"context"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type AuthorizationTransaction struct {
	State        string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

type Session struct {
	Token      *oauth2.Token
	RawIDToken string
	ExpiresAt  time.Time
}

// Store contains server-side authentication state.
//
// A production implementation could use Redis, SQL Server,
// PostgreSQL, or another shared store.
type Store interface {
	SaveTransaction(
		ctx context.Context,
		id string,
		transaction AuthorizationTransaction,
	) error

	GetTransaction(
		ctx context.Context,
		id string,
	) (AuthorizationTransaction, error)

	DeleteTransaction(
		ctx context.Context,
		id string,
	) error

	SaveSession(
		ctx context.Context,
		id string,
		session Session,
	) error

	GetSession(
		ctx context.Context,
		id string,
	) (Session, error)

	DeleteSession(
		ctx context.Context,
		id string,
	) error
}

type MemoryStore struct {
	mu           sync.RWMutex
	transactions map[string]AuthorizationTransaction
	sessions     map[string]Session
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		transactions: make(map[string]AuthorizationTransaction),
		sessions:     make(map[string]Session),
	}
}

func (s *MemoryStore) SaveTransaction(
	_ context.Context,
	id string,
	transaction AuthorizationTransaction,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeExpiredLocked(time.Now())
	s.transactions[id] = transaction

	return nil
}

func (s *MemoryStore) GetTransaction(
	_ context.Context,
	id string,
) (AuthorizationTransaction, error) {
	s.mu.RLock()

	transaction, found := s.transactions[id]

	s.mu.RUnlock()

	if !found {
		return AuthorizationTransaction{}, ErrSessionNotFound
	}

	if !transaction.ExpiresAt.IsZero() &&
		time.Now().After(transaction.ExpiresAt) {
		_ = s.DeleteTransaction(context.Background(), id)
		return AuthorizationTransaction{}, ErrSessionNotFound
	}

	return transaction, nil
}

func (s *MemoryStore) DeleteTransaction(
	_ context.Context,
	id string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.transactions, id)

	return nil
}

func (s *MemoryStore) SaveSession(
	_ context.Context,
	id string,
	session Session,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeExpiredLocked(time.Now())
	s.sessions[id] = cloneSession(session)

	return nil
}

func (s *MemoryStore) GetSession(
	_ context.Context,
	id string,
) (Session, error) {
	s.mu.RLock()

	session, found := s.sessions[id]

	s.mu.RUnlock()

	if !found {
		return Session{}, ErrSessionNotFound
	}

	if !session.ExpiresAt.IsZero() &&
		time.Now().After(session.ExpiresAt) {
		_ = s.DeleteSession(context.Background(), id)
		return Session{}, ErrSessionNotFound
	}

	return cloneSession(session), nil
}

func (s *MemoryStore) DeleteSession(
	_ context.Context,
	id string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)

	return nil
}

func (s *MemoryStore) removeExpiredLocked(now time.Time) {
	for id, transaction := range s.transactions {
		if !transaction.ExpiresAt.IsZero() &&
			now.After(transaction.ExpiresAt) {
			delete(s.transactions, id)
		}
	}

	for id, session := range s.sessions {
		if !session.ExpiresAt.IsZero() &&
			now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

func cloneSession(session Session) Session {
	copy := session

	if session.Token != nil {
		tokenCopy := *session.Token
		copy.Token = &tokenCopy
	}

	return copy
}
