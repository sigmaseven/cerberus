//go:generate mockgen -destination=mock_user.go -package=storage cerberus/storage UserStorage

//lint:file-ignore U1000 Mock implementation for user storage testing - used in integration tests
package storage

import (
	"context"
	"errors"
	"time"
)

// mockUserStorage implements UserStorage for testing
type mockUserStorage struct {
	users map[string]*User
}

func newMockUserStorage() *mockUserStorage {
	return &mockUserStorage{
		users: make(map[string]*User),
	}
}

func (m *mockUserStorage) CreateUser(ctx context.Context, user *User) error {
	if _, exists := m.users[user.Username]; exists {
		return errors.New("user already exists")
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.Active = true
	m.users[user.Username] = user
	return nil
}

func (m *mockUserStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user, exists := m.users[username]
	if !exists || !user.Active {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *mockUserStorage) UpdateUser(ctx context.Context, user *User) error {
	existing, exists := m.users[user.Username]
	if !exists {
		return errors.New("user not found")
	}
	user.UpdatedAt = time.Now()
	user.CreatedAt = existing.CreatedAt
	m.users[user.Username] = user
	return nil
}

func (m *mockUserStorage) DeleteUser(ctx context.Context, username string) error {
	user, exists := m.users[username]
	if !exists {
		return errors.New("user not found")
	}
	user.Active = false
	user.UpdatedAt = time.Now()
	return nil
}

func (m *mockUserStorage) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	for _, user := range m.users {
		if user.Active {
			users = append(users, user)
		}
	}
	return users, nil
}

func (m *mockUserStorage) ValidateCredentials(ctx context.Context, username, password string) (*User, error) {
	user, err := m.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	// For mock, just compare plain text (in real implementation, use bcrypt)
	if user.Password != password {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}
