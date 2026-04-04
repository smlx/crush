package dialog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/ui/common"
	"github.com/charmbracelet/crush/internal/ui/util"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

type OAuthProvider interface {
	name() string
	initiateAuth() tea.Msg
	startPolling(deviceCode string, expiresIn int) tea.Cmd
	stopPolling() tea.Msg
}

// OAuthState represents the current state of the device flow.
type OAuthState int

const (
	OAuthStateInitializing OAuthState = iota
	OAuthStateDisplay
	OAuthStateSuccess
	OAuthStateError
)

// OAuthID is the identifier for the model selection dialog.
const OAuthID = "oauth"

// OAuth handles the OAuth flow authentication.
type OAuth struct {
	com          *common.Common
	isOnboarding bool

	provider      catwalk.Provider
	model         config.SelectedModel
	modelType     config.SelectedModelType
	oAuthProvider OAuthProvider

	State OAuthState

	spinner spinner.Model
	help    help.Model
	keyMap  struct {
		Copy   key.Binding
		Submit key.Binding
		Close  key.Binding
	}

	width           int
	deviceCode      string
	userCode        string
	verificationURL string
	expiresIn       int
	interval        int
	token           *oauth.Token
	oauth2Token     *oauth2.Token
	cancelFunc      context.CancelFunc
	// onComplete, when non-nil, is called instead of saveKeyAndContinue when
	// the OAuth flow completes successfully.
	onComplete func(*oauth2.Token) Action
	onCancel   func() Action
}

var _ Dialog = (*OAuth)(nil)

// newOAuth creates a new device flow component.
func newOAuth(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
	oAuthProvider OAuthProvider,
	onComplete func(*oauth2.Token) Action,
	onCancel func() Action,
) (*OAuth, tea.Cmd) {
	t := com.Styles

	m := OAuth{}
	m.com = com
	m.isOnboarding = isOnboarding
	m.provider = provider
	m.model = model
	m.modelType = modelType
	m.oAuthProvider = oAuthProvider
	m.onComplete = onComplete
	m.onCancel = onCancel
	m.width = 80
	m.State = OAuthStateInitializing

	m.spinner = spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(t.Base.Foreground(t.GreenLight)),
	)

	m.help = help.New()
	m.help.Styles = t.DialogHelpStyles()

	m.keyMap.Copy = key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "copy code"),
	)
	m.keyMap.Submit = key.NewBinding(
		key.WithKeys("enter", "ctrl+y"),
		key.WithHelp("enter", "copy & open"),
	)
	m.keyMap.Close = CloseKey

	return &m, tea.Batch(m.spinner.Tick, m.oAuthProvider.initiateAuth)
}

// ID implements Dialog.
func (m *OAuth) ID() string {
	return OAuthID
}

// HandleMsg handles messages and state transitions.
func (m *OAuth) HandleMsg(msg tea.Msg) Action {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		switch m.State {
		case OAuthStateInitializing, OAuthStateDisplay:
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			if cmd != nil {
				return ActionCmd{cmd}
			}
		}

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.Copy):
			cmd := m.copyCode()
			return ActionCmd{cmd}

		case key.Matches(msg, m.keyMap.Submit):
			switch m.State {
			case OAuthStateSuccess:
				return m.complete()

			default:
				cmd := m.copyCodeAndOpenURL()
				return ActionCmd{cmd}
			}

		case key.Matches(msg, m.keyMap.Close):
			switch m.State {
			case OAuthStateSuccess:
				return m.complete()

			default:
				return m.cancel()
			}
		}

	case ActionInitiateOAuth:
		m.deviceCode = msg.DeviceCode
		m.userCode = msg.UserCode
		m.expiresIn = msg.ExpiresIn
		m.verificationURL = msg.VerificationURL
		m.interval = msg.Interval
		m.State = OAuthStateDisplay
		return ActionCmd{m.oAuthProvider.startPolling(msg.DeviceCode, msg.ExpiresIn)}

	case ActionCompleteOAuth:
		m.State = OAuthStateSuccess
		m.token = msg.Token
		return ActionCmd{m.oAuthProvider.stopPolling}

	case ActionCompleteMCPOAuth:
		m.State = OAuthStateSuccess
		m.oauth2Token = msg.Token
		return ActionCmd{m.oAuthProvider.stopPolling}

	case ActionOAuthErrored:
		m.State = OAuthStateError
		cmd := tea.Batch(m.oAuthProvider.stopPolling, util.ReportError(msg.Error))
		return ActionCmd{cmd}
	}
	return nil
}

// View renders the device flow dialog.
func (m *OAuth) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	var (
		t           = m.com.Styles
		dialogStyle = t.Dialog.View.Width(m.width)
	)
	if m.isOnboarding {
		view := m.dialogContent()
		DrawOnboarding(scr, area, view)
	} else {
		view := dialogStyle.Render(m.dialogContent())
		DrawCenter(scr, area, view)
	}
	return nil
}

func (m *OAuth) dialogContent() string {
	var (
		t         = m.com.Styles
		helpStyle = t.Dialog.HelpView
	)

	switch m.State {
	case OAuthStateInitializing:
		return m.innerDialogContent()

	default:
		elements := []string{
			m.headerContent(),
			m.innerDialogContent(),
			helpStyle.Render(m.help.View(m)),
		}
		return strings.Join(elements, "\n")
	}
}

func (m *OAuth) headerContent() string {
	var (
		t            = m.com.Styles
		titleStyle   = t.Dialog.Title
		textStyle    = t.Dialog.PrimaryText
		dialogStyle  = t.Dialog.View.Width(m.width)
		headerOffset = titleStyle.GetHorizontalFrameSize() + dialogStyle.GetHorizontalFrameSize()
		dialogTitle  = fmt.Sprintf("Authenticate with %s", m.oAuthProvider.name())
	)
	if m.isOnboarding {
		return textStyle.Render(dialogTitle)
	}
	return common.DialogTitle(t, titleStyle.Render(dialogTitle), m.width-headerOffset, t.Primary, t.Secondary)
}

func (m *OAuth) innerDialogContent() string {
	var (
		t            = m.com.Styles
		whiteStyle   = lipgloss.NewStyle().Foreground(t.White)
		primaryStyle = lipgloss.NewStyle().Foreground(t.Primary)
		greenStyle   = lipgloss.NewStyle().Foreground(t.GreenLight)
		linkStyle    = lipgloss.NewStyle().Foreground(t.GreenDark).Underline(true)
		errorStyle   = lipgloss.NewStyle().Foreground(t.Error)
		mutedStyle   = lipgloss.NewStyle().Foreground(t.FgMuted)
	)

	switch m.State {
	case OAuthStateInitializing:
		return lipgloss.NewStyle().
			Margin(1, 1).
			Width(m.width - 2).
			Align(lipgloss.Center).
			Render(
				greenStyle.Render(m.spinner.View()) +
					mutedStyle.Render("Initializing..."),
			)

	case OAuthStateDisplay:
		parts := []string{""}

		if m.userCode == "" {
			instructions := lipgloss.NewStyle().
				Margin(0, 1).
				Width(m.width - 2).
				Render(whiteStyle.Render("Press ") +
					primaryStyle.Render("enter") +
					whiteStyle.Render(" to copy the URL below and open it the browser."))
			parts = append(parts, instructions, "")
		} else {
			instructions := lipgloss.NewStyle().
				Margin(0, 1).
				Width(m.width - 2).
				Render(whiteStyle.Render("Press ") +
					primaryStyle.Render("enter") +
					whiteStyle.Render(" to copy the code below and open the browser."))

			codeBox := lipgloss.NewStyle().
				Width(m.width-2).
				Height(7).
				Align(lipgloss.Center, lipgloss.Center).
				Background(t.BgBaseLighter).
				Margin(0, 1).
				Render(
					lipgloss.NewStyle().
						Bold(true).
						Foreground(t.White).
						Render(m.userCode),
				)
			parts = append(parts, instructions, "", codeBox, "")
		}

		link := linkStyle.Hyperlink(m.verificationURL, "id=oauth-verify").Render(m.verificationURL)
		url := mutedStyle.
			Margin(0, 1).
			Width(m.width - 2).
			Render("Browser not opening? Refer to\n" + link)

		waiting := lipgloss.NewStyle().
			Margin(0, 1).
			Width(m.width - 2).
			Render(
				greenStyle.Render(m.spinner.View()) + mutedStyle.Render("Verifying..."),
			)

		parts = append(parts, url, "", waiting, "")

		return lipgloss.JoinVertical(lipgloss.Left, parts...)

	case OAuthStateSuccess:
		return greenStyle.
			Margin(1).
			Width(m.width - 2).
			Render("Authentication successful!")

	case OAuthStateError:
		return lipgloss.NewStyle().
			Margin(1).
			Width(m.width - 2).
			Render(errorStyle.Render("Authentication failed."))

	default:
		return ""
	}
}

// FullHelp returns the full help view.
func (m *OAuth) FullHelp() [][]key.Binding {
	return [][]key.Binding{m.ShortHelp()}
}

// ShortHelp returns the full help view.
func (m *OAuth) ShortHelp() []key.Binding {
	switch m.State {
	case OAuthStateError:
		return []key.Binding{m.keyMap.Close}

	case OAuthStateSuccess:
		return []key.Binding{
			key.NewBinding(
				key.WithKeys("enter", "ctrl+y", "esc"),
				key.WithHelp("enter", "finish"),
			),
		}

	default:
		bindings := []key.Binding{}
		if m.userCode != "" {
			bindings = append(bindings, m.keyMap.Copy)
		}
		bindings = append(bindings, m.keyMap.Submit, m.keyMap.Close)
		return bindings
	}
}

func (d *OAuth) copyCode() tea.Cmd {
	if d.State != OAuthStateDisplay || d.userCode == "" {
		return nil
	}
	return tea.Sequence(
		tea.SetClipboard(d.userCode),
		util.ReportInfo("Code copied to clipboard"),
	)
}

func (d *OAuth) copyCodeAndOpenURL() tea.Cmd {
	if d.State != OAuthStateDisplay {
		return nil
	}
	var cmds []tea.Cmd
	var infoMsg string
	var errMsg string
	if d.userCode == "" {
		infoMsg = "URL copied to clipboard and opened in browser"
		errMsg = "failed to open browser. URL is on your clipboard"
		cmds = append(cmds, tea.SetClipboard(d.verificationURL))
	} else {
		infoMsg = "Code copied and URL opened"
		errMsg = "failed to open browser. Code is on your clipboard"
		cmds = append(cmds, tea.SetClipboard(d.userCode))
	}
	cmds = append(cmds,
		func() tea.Msg {
			// xdg-open has return code 0 on some errors, so also check stderr which
			// should be empty on success.
			var stderrBuf bytes.Buffer
			browser.Stderr = &stderrBuf
			err := browser.OpenURL(d.verificationURL)
			if err != nil || stderrBuf.Len() > 0 {
				return util.ReportError(errors.New(errMsg))()
			}
			return util.ReportInfo(infoMsg)()
		},
	)
	return tea.Sequence(cmds...)
}

// complete is called when the OAuth flow succeeds. If onComplete is set it
// delegates to it; otherwise it falls back to the default provider key save.
func (m *OAuth) complete() Action {
	if m.onComplete != nil {
		return m.onComplete(m.oauth2Token)
	}
	return m.saveKeyAndContinue()
}

func (m *OAuth) cancel() Action {
	if m.onCancel != nil {
		return m.onCancel()
	}
	return ActionClose{}
}

func (m *OAuth) saveKeyAndContinue() Action {
	err := m.com.Workspace.SetProviderAPIKey(config.ScopeGlobal, string(m.provider.ID), m.token)
	if err != nil {
		return ActionCmd{util.ReportError(fmt.Errorf("failed to save API key: %w", err))}
	}

	return ActionSelectModel{
		Provider:  m.provider,
		Model:     m.model,
		ModelType: m.modelType,
	}
}
