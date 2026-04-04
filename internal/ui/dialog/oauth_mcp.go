package dialog

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/ui/common"
	"golang.org/x/oauth2"
)

// OAuthMCP implements OAuthProvider for MCP OAuth2 authorization code flow.
type OAuthMCP struct {
	mcpName string
	authURL string
}

var _ OAuthProvider = (*OAuthMCP)(nil)

// NewOAuthMCP creates an OAuth dialog for MCP server authorization.
func NewOAuthMCP(
	com *common.Common,
	mcpName, authURL string,
) (*OAuth, tea.Cmd) {
	provider := &OAuthMCP{
		mcpName: mcpName,
		authURL: authURL,
	}
	return newOAuth(
		com,
		false,
		catwalk.Provider{},
		config.SelectedModel{},
		"",
		provider,
		func(_ *oauth2.Token) Action { return ActionClose{} },
		func() Action { return ActionCancelMCPOAuth{Name: mcpName} },
	)
}

func (m *OAuthMCP) name() string {
	return fmt.Sprintf("MCP: %s", m.mcpName)
}

func (m *OAuthMCP) initiateAuth() tea.Msg {
	return ActionInitiateOAuth{VerificationURL: m.authURL}
}

// startPolling stub to satisfy the interface even though the OAuth2
// authorization code flow doesn't require polling.
func (m *OAuthMCP) startPolling(_ string, _ int) tea.Cmd {
	return nil
}

// stopPolling stub to satisfy the interface even though the OAuth2
// authorization code flow doesn't require polling.
func (m *OAuthMCP) stopPolling() tea.Msg {
	return nil
}
