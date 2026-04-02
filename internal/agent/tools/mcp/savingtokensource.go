package mcp

import (
	"log/slog"
	"sync"

	"golang.org/x/oauth2"
)

// NewSavingTokenSource persists OAuth 2.0 sessions by intercepting token
// refreshes from the wrapped oauth2.TokenSource. When this wrapper detects
// an access token refresh, it calls the provided session saver with the
// oauth2.Config and the new oauth2.Token.
//
// The initial token argument prevents saver from being called unnecessarily if
// a valid token already exists. If initial is invalid or nil, saver may be
// called once before the wrapped token is refreshed.
func NewSavingTokenSource(wrapped oauth2.TokenSource, config *oauth2.Config, initialToken *oauth2.Token, saver func(*oauth2.Config, *oauth2.Token)) oauth2.TokenSource {
	if wrapped == nil {
		return nil
	}
	if saver == nil {
		return wrapped
	}
	var accessToken string
	if initialToken != nil {
		accessToken = initialToken.AccessToken
	}
	return &savingTokenSource{
		src:         wrapped,
		saver:       saver,
		config:      config,
		accessToken: accessToken,
	}
}

// savingTokenSource is an oauth2.TokenSource that saves the config and
// token to the given saver function each time the token is refreshed.
type savingTokenSource struct {
	mu          sync.Mutex
	src         oauth2.TokenSource
	saver       func(*oauth2.Config, *oauth2.Token)
	config      *oauth2.Config
	accessToken string
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	slog.Debug("Getting token from saving token source!!!")
	tok, err := s.src.Token()
	if err != nil {
		slog.Debug("Couldn't refresh token!!!", "error", err)
		return nil, err
	}
	s.mu.Lock()
	changed := s.accessToken != tok.AccessToken
	if changed {
		s.accessToken = tok.AccessToken
	}
	s.mu.Unlock()
	if changed {
		s.saver(s.config, tok)
	}
	return tok, nil
}
