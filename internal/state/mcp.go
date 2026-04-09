package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/oauth2"
)

var ErrNoStore = errors.New("no store file found")

type MCPStore struct {
	mu   sync.RWMutex
	path string
}

type MCPOAuth2 struct {
	Config *oauth2.Config `json:"config,omitempty"`
	Token  *oauth2.Token  `json:"token,omitempty"`
}

type mcpState struct {
	MCPOAuth2
	Headers map[string]string `json:"headers,omitempty"`
}

func NewMCPStore(name string) (*MCPStore, error) {
	stateDir, ok := os.LookupEnv("XDG_STATE_HOME")
	if !ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		stateDir = filepath.Join(home, ".local", "state")
	}
	path := filepath.Join(stateDir, "crush", "mcp")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	return &MCPStore{
		path: filepath.Join(path, name+".json"),
	}, nil
}

func (s *MCPStore) SaveOAuth2Config(cfg *oauth2.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadNoLock()
	if err != nil && err != ErrNoStore {
		return err
	}
	if state == nil {
		state = &mcpState{}
	}
	state.Config = cfg

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *MCPStore) SaveOAuth2Token(tok *oauth2.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadNoLock()
	if err != nil && err != ErrNoStore {
		return err
	}
	if state == nil {
		state = &mcpState{}
	}
	state.Token = tok

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *MCPStore) SaveHeaders(headers map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadNoLock()
	if err != nil && err != ErrNoStore {
		return err
	}
	if state == nil {
		state = &mcpState{}
	}
	state.Headers = headers

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *MCPStore) loadNoLock() (*mcpState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoStore
		}
		return nil, err
	}

	var state mcpState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func (s *MCPStore) LoadOAuth2() (*MCPOAuth2, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, err := s.loadNoLock()
	if err != nil {
		return nil, err
	}
	return &state.MCPOAuth2, nil
}

func (s *MCPStore) LoadHeaders() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, err := s.loadNoLock()
	if err != nil {
		return nil, err
	}
	return state.Headers, nil
}
