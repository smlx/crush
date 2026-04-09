// Package mcp provides functionality for managing Model Context Protocol (MCP)
// clients within the Crush application.
package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/home"
	"github.com/charmbracelet/crush/internal/permission"
	"github.com/charmbracelet/crush/internal/pubsub"
	"github.com/charmbracelet/crush/internal/state"
	"github.com/charmbracelet/crush/internal/version"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

func parseLevel(level mcp.LoggingLevel) slog.Level {
	switch level {
	case "info":
		return slog.LevelInfo
	case "notice":
		return slog.LevelInfo
	case "warning":
		return slog.LevelWarn
	default:
		return slog.LevelDebug
	}
}

var (
	sessions    = csync.NewMap[string, *mcp.ClientSession]()
	states      = csync.NewMap[string, ClientInfo]()
	broker      = pubsub.NewBroker[Event]()
	authCancels = csync.NewMap[string, context.CancelFunc]()
	initOnce    sync.Once
	initDone    = make(chan struct{})

	// oauthCallbackPorts defines the local TCP ports to try binding to for the
	// OAuth2 callback server for the authorization code flow.
	oauthCallbackPorts = []int{49433, 52829, 54257}
	// oauthClientMetadataURL defines the URL required by
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-01
	oauthClientMetadataURL = "https://charm.land/crush/oauth-client-metadata.json"
)

// State represents the current state of an MCP client
type State int

const (
	StateDisabled State = iota
	StateStarting
	StateConnected
	StateError
)

func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateStarting:
		return "starting"
	case StateConnected:
		return "connected"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// EventType represents the type of MCP event
type EventType uint

const (
	EventStateChanged EventType = iota
	EventToolsListChanged
	EventPromptsListChanged
	EventResourcesListChanged
	// EventAuthRequired is published when an HTTP/SSE MCP server responds with
	// 401 Unauthorized and the client must complete an OAuth2 authorization
	// flow before retrying.
	EventAuthRequired
	// EventAuthCompleted is published when an OAuth2 authorization flow
	// completes successfully.
	EventAuthCompleted
	// EventAuthFailed is published when an OAuth2 authorization flow fails.
	EventAuthFailed
)

// Event represents an event in the MCP system
type Event struct {
	Type   EventType
	Name   string
	State  State
	Error  error
	Counts Counts
	// AuthURL is the OAuth2 authorization URL that needs to be opened in a
	// browser. Populated only for EventAuthRequired events.
	AuthURL string
}

// Counts number of available tools, prompts, etc.
type Counts struct {
	Tools     int
	Prompts   int
	Resources int
}

// ClientInfo holds information about an MCP client's state
type ClientInfo struct {
	Name        string
	State       State
	Error       error
	Client      *mcp.ClientSession
	Counts      Counts
	ConnectedAt time.Time
}

// SubscribeEvents returns a channel for MCP events
func SubscribeEvents(ctx context.Context) <-chan pubsub.Event[Event] {
	return broker.Subscribe(ctx)
}

// CancelAuth cancels a pending OAuth2 authorization flow.
func CancelAuth(name string) {
	cancel, ok := authCancels.Get(name)
	if !ok {
		return
	}
	cancel()
}

// GetStates returns the current state of all MCP clients
func GetStates() map[string]ClientInfo {
	return states.Copy()
}

// GetState returns the state of a specific MCP client
func GetState(name string) (ClientInfo, bool) {
	return states.Get(name)
}

// Close closes all MCP clients. This should be called during application shutdown.
func Close(ctx context.Context) error {
	var wg sync.WaitGroup
	for name, session := range sessions.Seq2() {
		wg.Go(func() {
			done := make(chan error, 1)
			go func() {
				done <- session.Close()
			}()
			select {
			case err := <-done:
				if err != nil &&
					!errors.Is(err, io.EOF) &&
					!errors.Is(err, context.Canceled) &&
					err.Error() != "signal: killed" {
					slog.Warn("Failed to shutdown MCP client", "name", name, "error", err)
				}
			case <-ctx.Done():
			}
		})
	}
	wg.Wait()
	broker.Shutdown()
	return nil
}

// Initialize initializes MCP clients based on the provided configuration.
func Initialize(ctx context.Context, permissions permission.Service, cfg *config.ConfigStore) {
	slog.Info("Initializing MCP clients")
	var wg sync.WaitGroup
	// Initialize states for all configured MCPs
	for name, m := range cfg.Config().MCP {
		if m.Disabled {
			updateState(name, StateDisabled, nil, nil, Counts{})
			slog.Debug("Skipping disabled MCP", "name", name)
			continue
		}

		// Set initial starting state
		wg.Add(1)
		go func(name string, m config.MCPConfig) {
			defer func() {
				wg.Done()
				if r := recover(); r != nil {
					var err error
					switch v := r.(type) {
					case error:
						err = v
					case string:
						err = fmt.Errorf("panic: %s", v)
					default:
						err = fmt.Errorf("panic: %v", v)
					}
					updateState(name, StateError, err, nil, Counts{})
					slog.Error("Panic in MCP client initialization", "error", err, "name", name)
				}
			}()

			if err := initClient(ctx, cfg, name, m, cfg.Resolver()); err != nil {
				slog.Debug("Failed to initialize MCP client", "name", name, "error", err)
			}
		}(name, m)
	}
	wg.Wait()
	initOnce.Do(func() { close(initDone) })
}

// WaitForInit blocks until MCP initialization is complete.
// If Initialize was never called, this returns immediately.
func WaitForInit(ctx context.Context) error {
	select {
	case <-initDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// InitializeSingle initializes a single MCP client by name.
func InitializeSingle(ctx context.Context, name string, cfg *config.ConfigStore) error {
	m, exists := cfg.Config().MCP[name]
	if !exists {
		return fmt.Errorf("mcp '%s' not found in configuration", name)
	}

	if m.Disabled {
		updateState(name, StateDisabled, nil, nil, Counts{})
		slog.Debug("Skipping disabled MCP", "name", name)
		return nil
	}

	return initClient(ctx, cfg, name, m, cfg.Resolver())
}

// initClient initializes a single MCP client with the given configuration.
func initClient(ctx context.Context, cfg *config.ConfigStore, name string, m config.MCPConfig, resolver config.VariableResolver) error {
	// Set initial starting state.
	updateState(name, StateStarting, nil, nil, Counts{})

	// createSession handles its own timeout internally.
	session, err := createSession(ctx, name, m, resolver)
	if err != nil {
		return err
	}

	tools, err := getTools(ctx, session)
	if err != nil {
		slog.Error("Error listing tools", "error", err)
		updateState(name, StateError, err, nil, Counts{})
		session.Close()
		return err
	}

	prompts, err := getPrompts(ctx, session)
	if err != nil {
		slog.Error("Error listing prompts", "error", err)
		updateState(name, StateError, err, nil, Counts{})
		session.Close()
		return err
	}

	toolCount := updateTools(cfg, name, tools)
	updatePrompts(name, prompts)
	sessions.Set(name, session)

	updateState(name, StateConnected, nil, session, Counts{
		Tools:   toolCount,
		Prompts: len(prompts),
	})

	return nil
}

// DisableSingle disables and closes a single MCP client by name.
func DisableSingle(cfg *config.ConfigStore, name string) error {
	session, ok := sessions.Get(name)
	if ok {
		if err := session.Close(); err != nil &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, context.Canceled) &&
			err.Error() != "signal: killed" {
			slog.Warn("Error closing MCP session", "name", name, "error", err)
		}
		sessions.Del(name)
	}

	// Clear tools and prompts for this MCP.
	updateTools(cfg, name, nil)
	updatePrompts(name, nil)

	// Update state to disabled.
	updateState(name, StateDisabled, nil, nil, Counts{})

	slog.Info("Disabled mcp client", "name", name)
	return nil
}

func getOrRenewClient(ctx context.Context, cfg *config.ConfigStore, name string) (*mcp.ClientSession, error) {
	sess, ok := sessions.Get(name)
	if !ok {
		return nil, fmt.Errorf("mcp '%s' not available", name)
	}

	m := cfg.Config().MCP[name]
	state, _ := states.Get(name)

	timeout := mcpTimeout(m)
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := sess.Ping(pingCtx, nil)
	if err == nil {
		return sess, nil
	}
	updateState(name, StateError, maybeTimeoutErr(err, timeout), nil, state.Counts)

	sess, err = createSession(ctx, name, m, cfg.Resolver())
	if err != nil {
		return nil, err
	}

	updateState(name, StateConnected, nil, sess, state.Counts)
	sessions.Set(name, sess)
	return sess, nil
}

// updateState updates the state of an MCP client and publishes an event
func updateState(name string, state State, err error, client *mcp.ClientSession, counts Counts) {
	info := ClientInfo{
		Name:   name,
		State:  state,
		Error:  err,
		Client: client,
		Counts: counts,
	}
	switch state {
	case StateConnected:
		info.ConnectedAt = time.Now()
	case StateError:
		sessions.Del(name)
	}
	states.Set(name, info)

	// Publish state change event
	broker.Publish(pubsub.UpdatedEvent, Event{
		Type:   EventStateChanged,
		Name:   name,
		State:  state,
		Error:  err,
		Counts: counts,
	})
}

func createSession(ctx context.Context, name string, m config.MCPConfig, resolver config.VariableResolver) (*mcp.ClientSession, error) {
	timeout := mcpTimeout(m)
	mcpCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport, err := createTransport(mcpCtx, name, m, resolver)
	if err != nil {
		updateState(name, StateError, err, nil, Counts{})
		slog.Error("Error creating MCP client", "error", err, "name", name)
		return nil, err
	}

	client := mcp.NewClient(
		&mcp.Implementation{
			Name:    "crush",
			Version: version.Version,
			Title:   "Crush",
		},
		&mcp.ClientOptions{
			ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventToolsListChanged,
					Name: name,
				})
			},
			PromptListChangedHandler: func(context.Context, *mcp.PromptListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventPromptsListChanged,
					Name: name,
				})
			},
			ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) {
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type: EventResourcesListChanged,
					Name: name,
				})
			},
			LoggingMessageHandler: func(ctx context.Context, req *mcp.LoggingMessageRequest) {
				level := parseLevel(req.Params.Level)
				slog.Log(ctx, level, "MCP log", "name", name, "logger", req.Params.Logger, "data", req.Params.Data)
			},
		},
	)

	session, err := client.Connect(mcpCtx, transport, nil)
	if err != nil {
		err = maybeStdioErr(err, transport)
		updateState(name, StateError, maybeTimeoutErr(err, timeout), nil, Counts{})
		slog.Error("MCP client failed to initialize", "error", err, "name", name)
		return nil, err
	}

	slog.Debug("MCP client initialized", "name", name)
	return session, nil
}

// maybeStdioErr if a stdio mcp prints an error in non-json format, it'll fail
// to parse, and the cli will then close it, causing the EOF error.
// so, if we got an EOF err, and the transport is STDIO, we try to exec it
// again with a timeout and collect the output so we can add details to the
// error.
// this happens particularly when starting things with npx, e.g. if node can't
// be found or some other error like that.
func maybeStdioErr(err error, transport mcp.Transport) error {
	if !errors.Is(err, io.EOF) {
		return err
	}
	ct, ok := transport.(*mcp.CommandTransport)
	if !ok {
		return err
	}
	if err2 := stdioCheck(ct.Command); err2 != nil {
		err = errors.Join(err, err2)
	}
	return err
}

func maybeTimeoutErr(err error, timeout time.Duration) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s", timeout)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("cancelled")
	}
	return err
}

func mcpHeaders(m config.MCPConfig, store *state.MCPStore) map[string]string {
	headers := maps.Clone(m.ResolvedHeaders())
	if headers == nil {
		headers = map[string]string{}
	}
	if storeHeaders, err := store.LoadHeaders(); err == nil {
		maps.Copy(headers, storeHeaders)
	}
	return headers
}

func createTransport(ctx context.Context, name string, m config.MCPConfig, resolver config.VariableResolver) (mcp.Transport, error) {
	switch m.Type {
	case config.MCPStdio:
		command, err := resolver.ResolveValue(m.Command)
		if err != nil {
			return nil, fmt.Errorf("invalid mcp command: %w", err)
		}
		if strings.TrimSpace(command) == "" {
			return nil, fmt.Errorf("mcp stdio config requires a non-empty 'command' field")
		}
		cmd := exec.CommandContext(ctx, home.Long(command), m.Args...)
		cmd.Env = append(os.Environ(), m.ResolvedEnv()...)
		return &mcp.CommandTransport{
			Command: cmd,
		}, nil
	case config.MCPHttp:
		store, err := state.NewMCPStore(name)
		if err != nil {
			return nil, fmt.Errorf("couldn't init MCP state store: %v", err)
		}
		if strings.TrimSpace(m.URL) == "" {
			return nil, fmt.Errorf("mcp http config requires a non-empty 'url' field")
		}
		client := &http.Client{
			Transport: &headerRoundTripper{headers: mcpHeaders(m, store)},
		}
		return &mcp.StreamableClientTransport{
			Endpoint:     m.URL,
			HTTPClient:   client,
			OAuthHandler: &crushOAuthHandler{store: store, name: name, mcpURL: m.URL},
		}, nil
	case config.MCPSSE:
		store, err := state.NewMCPStore(name)
		if err != nil {
			return nil, fmt.Errorf("couldn't init MCP state store: %v", err)
		}
		if strings.TrimSpace(m.URL) == "" {
			return nil, fmt.Errorf("mcp sse config requires a non-empty 'url' field")
		}
		client := &http.Client{
			Transport: &headerRoundTripper{headers: mcpHeaders(m, store)},
		}
		return &mcp.SSEClientTransport{
			Endpoint:   m.URL,
			HTTPClient: client,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported mcp type: %s", m.Type)
	}
}

type headerRoundTripper struct {
	headers map[string]string
}

func (rt headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range rt.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

type crushOAuthHandler struct {
	store  *state.MCPStore
	name   string
	mcpURL string

	// retry loop detection
	mu           sync.Mutex
	authAttempts int
	lastAuth     time.Time
}

// tokenSourceFunc implements an oauth2.TokenSource adapter pattern.
type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) {
	return f()
}

// TokenSource will save tokens to the MCPOAuth2Store on each refresh.
func (h *crushOAuthHandler) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	st, err := h.store.LoadOAuth2()
	if errors.Is(err, state.ErrNoStore) {
		return nil, nil // no error, just no token available
	}
	if err != nil {
		return nil, fmt.Errorf("couldn't load MCP OAuth2 state: %v", err)
	}

	if st.Config != nil {
		base := st.Config.TokenSource(ctx, st.Token)
		return tokenSourceFunc(func() (*oauth2.Token, error) {
			newTok, err := base.Token()
			if err != nil {
				return nil, err
			}
			if st.Token == nil || newTok.AccessToken != st.Token.AccessToken || newTok.RefreshToken != st.Token.RefreshToken {
				st.Token = newTok
				if err := h.store.SaveOAuth2Token(newTok); err != nil {
					slog.Warn("Failed to save MCP OAuth2 token", "name", h.name, "error", err)
				}
			}
			return newTok, nil
		}), nil
	}

	return oauth2.StaticTokenSource(st.Token), nil
}

func (h *crushOAuthHandler) Authorize(ctx context.Context, req *http.Request, resp *http.Response) error {
	authCtx, authCancel := context.WithCancel(ctx)
	defer authCancel()
	authCancels.Set(h.name, authCancel)
	defer authCancels.Del(h.name)

	// check for retry loop
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if now.Sub(h.lastAuth) > time.Minute {
		h.authAttempts = 0
	}
	h.authAttempts++
	h.lastAuth = now
	if h.authAttempts > 3 {
		return fmt.Errorf("authorization retry limit exceeded: potential infinite scope step-up loop detected")
	}
	// load existing config and token, if possible
	st, err := h.store.LoadOAuth2()
	if err != nil {
		if err != state.ErrNoStore {
			return fmt.Errorf("couldn't load oauth2 state: %v", err)
		}
		st = &state.MCPOAuth2{}
	}

	// force token refresh to return early and avoid interactive flow if possible
	if st.Config != nil && st.Token != nil && st.Token.RefreshToken != "" {
		st.Token.Expiry = time.Now().Add(-time.Hour)
		newTok, err := st.Config.TokenSource(ctx, st.Token).Token()
		if err == nil && newTok.Valid() {
			if err := h.store.SaveOAuth2Token(newTok); err != nil {
				slog.Warn("Failed to save MCP OAuth2 token", "name", h.name, "error", err)
			}
			return nil
		}
	}
	// use pre-registered client credentials if available
	var preReg *oauthex.ClientCredentials
	if st.Config != nil && st.Config.ClientID != "" {
		preReg = &oauthex.ClientCredentials{
			ClientID: st.Config.ClientID,
		}
		if st.Config.ClientSecret != "" {
			preReg.ClientSecretAuth = &oauthex.ClientSecretAuth{
				ClientSecret: st.Config.ClientSecret,
			}
		}
	}
	// create a listener on one of the valid redirect URI ports
	var ln net.Listener
	for _, port := range oauthCallbackPorts {
		ln, err = (&net.ListenConfig{}).
			Listen(authCtx, "tcp", fmt.Sprintf("localhost:%d", port))
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("couldn't create listener for oauth2 callback on any of the specified ports: %v", err)
	}
	defer ln.Close()
	// construct the redirect URI
	redirectURI := fmt.Sprintf("http://localhost:%d/callback",
		ln.Addr().(*net.TCPAddr).Port)
	// configure the mcp go-sdk authz code handler
	authCfg := &auth.AuthorizationCodeHandlerConfig{
		ClientIDMetadataDocumentConfig: &auth.ClientIDMetadataDocumentConfig{
			URL: oauthClientMetadataURL,
		},
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{
			Metadata: &oauthex.ClientRegistrationMetadata{
				ClientName:              "Crush",
				ClientURI:               "https://github.com/charmbracelet/crush",
				RedirectURIs:            []string{redirectURI},
				TokenEndpointAuthMethod: "none",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
			},
		},
		PreregisteredClient: preReg,
		RedirectURL:         redirectURI,
		OAuth2ConfigCallback: func(cfg *oauth2.Config) {
			if err := h.store.SaveOAuth2Config(cfg); err != nil {
				slog.Warn("Failed to save MCP OAuth2 state", "name", h.name, "error", err)
			}
		},
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			broker.Publish(pubsub.UpdatedEvent, Event{
				Type:    EventAuthRequired,
				Name:    h.name,
				AuthURL: args.URL,
			})

			codeCh := make(chan string, 1)
			stateCh := make(chan string, 1)
			errCh := make(chan error, 1)

			srv := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					q := r.URL.Query()
					stateParam := q.Get("state")
					code := q.Get("code")
					if code == "" {
						desc := q.Get("error_description")
						if desc == "" {
							desc = q.Get("error")
						}
						http.Error(w, "authorization failed", http.StatusBadRequest)
						errCh <- fmt.Errorf("authorization failed: %s", desc)
						return
					}
					fmt.Fprintln(w, "Authorization successful. You may close this tab.")
					stateCh <- stateParam
					codeCh <- code
				}),
			}

			go func() {
				if srvErr := srv.Serve(ln); srvErr != nil && srvErr != http.ErrServerClosed {
					errCh <- srvErr
				}
			}()
			defer srv.Close()

			select {
			case <-ctx.Done():
				err := ctx.Err()
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type:  EventAuthFailed,
					Name:  h.name,
					Error: fmt.Errorf("authorization failed: %v", err),
				})
				return nil, err
			case err := <-errCh:
				broker.Publish(pubsub.UpdatedEvent, Event{
					Type:  EventAuthFailed,
					Name:  h.name,
					Error: err,
				})
				return nil, err
			case code := <-codeCh:
				stateParam := <-stateCh
				return &auth.AuthorizationResult{
					Code:  code,
					State: stateParam,
				}, nil
			}
		},
	}

	// run the auth code flow
	sdkHandler, err := auth.NewAuthorizationCodeHandler(authCfg)
	if err != nil {
		return fmt.Errorf("couldn't create authz code handler: %v", err)
	}
	if err := sdkHandler.Authorize(authCtx, req, resp); err != nil {
		return fmt.Errorf("couldn't perform authz flow: %v", err)
	}
	ts, err := sdkHandler.TokenSource(authCtx)
	if err != nil {
		return fmt.Errorf("couldn't get token source: %v", err)
	}
	newTok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("couldn't get token: %v", err)
	}
	if err := h.store.SaveOAuth2Token(newTok); err != nil {
		return fmt.Errorf("couldn't store token: %v", err)
	}

	broker.Publish(pubsub.UpdatedEvent, Event{
		Type: EventAuthCompleted,
		Name: h.name,
	})

	return nil
}

func mcpTimeout(m config.MCPConfig) time.Duration {
	return time.Duration(cmp.Or(m.Timeout, 60)) * time.Second
}

func stdioCheck(old *exec.Cmd) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	cmd := exec.CommandContext(ctx, old.Path, old.Args...)
	cmd.Env = old.Env
	out, err := cmd.CombinedOutput()
	if err == nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil
	}
	return fmt.Errorf("%w: %s", err, string(out))
}
