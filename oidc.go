package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultTransactionCookieName = "oidc_transaction"
	defaultSessionCookieName     = "oidc_session"

	defaultTransactionLifetime = 5 * time.Minute
	defaultSessionLifetime     = 8 * time.Hour
)

var (
	defaultRequestedScopes = []string{
		oidc.ScopeOpenID,
		"profile",
		"email",
	}

	// These defaults cover common provider conventions while exposing one
	// normalized Roles collection to applications. Callers can replace or extend
	// them through AuthorizationConfig.RoleClaimPaths.
	defaultRoleClaimPaths = []string{
		"roles",
		"role",
		"groups",
		"realm_access.roles",
		"resource_access.{client_id}.roles",
	}

	defaultScopeClaimPaths = []string{
		"scope",
		"scp",
	}
)

type AuthorizationConfig struct {
	// RoleClaimPaths identifies claims containing roles. Paths may refer to
	// nested objects with dot notation and may use {client_id} as a placeholder.
	RoleClaimPaths []string

	// ScopeClaimPaths identifies claims containing granted scopes. The package
	// examines token-response extras and merged OIDC claims.
	ScopeClaimPaths []string

	// LoadUserInfo merges claims from the provider's UserInfo endpoint with the
	// verified ID-token claims before roles and scopes are normalized.
	LoadUserInfo bool
}

type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string

	// Logger receives debug-level lifecycle events from the auth package.
	// When nil, logging is disabled.
	Logger *slog.Logger

	// RequestedScopes contains additional scopes requested by the application.
	// The package always includes openid and defaults to profile and email when
	// this field is empty.
	RequestedScopes []string

	Authorization AuthorizationConfig
	Store         Store

	TransactionCookieName string
	SessionCookieName     string

	TransactionLifetime time.Duration
	SessionLifetime     time.Duration

	CookieSecure   bool
	CookieSameSite http.SameSite

	LoginSuccessURL string
	ErrorHandler    ErrorHandler
}

type Client struct {
	oauth2Config oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	store        Store
	logger       *slog.Logger

	authorization AuthorizationConfig

	transactionCookieName string
	sessionCookieName     string

	transactionLifetime time.Duration
	sessionLifetime     time.Duration

	cookieSecure   bool
	cookieSameSite http.SameSite

	loginSuccessURL string
	errorHandler    ErrorHandler
}

func New(ctx context.Context, config Config) (*Client, error) {
	const operation = "auth.New"

	if ctx == nil {
		return nil, wrapError(
			operation,
			"invalid_context",
			"context is required",
			ErrInvalidConfiguration,
		)
	}

	if strings.TrimSpace(config.IssuerURL) == "" {
		return nil, configError(operation, "IssuerURL is required")
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return nil, configError(operation, "ClientID is required")
	}
	if strings.TrimSpace(config.RedirectURL) == "" {
		return nil, configError(operation, "RedirectURL is required")
	}
	if config.Store == nil {
		return nil, configError(operation, "Store is required")
	}

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, wrapError(
			operation,
			"provider_discovery_failed",
			"OIDC provider discovery failed",
			fmt.Errorf("%w: %v", ErrInvalidConfiguration, err),
		)
	}

	scopes := normalizeRequestedScopes(config.RequestedScopes)
	authorization := normalizeAuthorizationConfig(config.Authorization)

	transactionCookieName := config.TransactionCookieName
	if transactionCookieName == "" {
		transactionCookieName = defaultTransactionCookieName
	}

	sessionCookieName := config.SessionCookieName
	if sessionCookieName == "" {
		sessionCookieName = defaultSessionCookieName
	}

	transactionLifetime := config.TransactionLifetime
	if transactionLifetime <= 0 {
		transactionLifetime = defaultTransactionLifetime
	}

	sessionLifetime := config.SessionLifetime
	if sessionLifetime <= 0 {
		sessionLifetime = defaultSessionLifetime
	}

	sameSite := config.CookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}

	successURL := config.LoginSuccessURL
	if successURL == "" {
		successURL = "/"
	}

	errorHandler := config.ErrorHandler
	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &Client{
		oauth2Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: config.ClientID,
		}),
		store:         config.Store,
		logger:        logger,
		authorization: authorization,

		transactionCookieName: transactionCookieName,
		sessionCookieName:     sessionCookieName,
		transactionLifetime:   transactionLifetime,
		sessionLifetime:       sessionLifetime,
		cookieSecure:          config.CookieSecure,
		cookieSameSite:        sameSite,
		loginSuccessURL:       successURL,
		errorHandler:          errorHandler,
	}, nil
}

func normalizeRequestedScopes(requested []string) []string {
	if len(requested) == 0 {
		return append([]string(nil), defaultRequestedScopes...)
	}

	values := make([]string, 0, len(requested)+1)
	values = append(values, oidc.ScopeOpenID)
	values = append(values, requested...)
	return uniqueStrings(values)
}

func normalizeAuthorizationConfig(config AuthorizationConfig) AuthorizationConfig {
	if len(config.RoleClaimPaths) == 0 {
		config.RoleClaimPaths = append([]string(nil), defaultRoleClaimPaths...)
	} else {
		config.RoleClaimPaths = uniqueStrings(config.RoleClaimPaths)
	}

	if len(config.ScopeClaimPaths) == 0 {
		config.ScopeClaimPaths = append([]string(nil), defaultScopeClaimPaths...)
	} else {
		config.ScopeClaimPaths = uniqueStrings(config.ScopeClaimPaths)
	}

	return config
}

func configError(operation, message string) error {
	return wrapError(operation, "invalid_configuration", message, ErrInvalidConfiguration)
}

func (c *Client) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.beginLogin(w, r); err != nil {
			c.errorHandler(w, r, err)
		}
	})
}

func (c *Client) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.completeLogin(w, r); err != nil {
			c.errorHandler(w, r, err)
		}
	})
}

func (c *Client) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := c.logout(w, r); err != nil {
			c.errorHandler(w, r, err)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func (c *Client) beginLogin(w http.ResponseWriter, r *http.Request) error {
	const operation = "auth.Client.beginLogin"

	c.logger.Debug("starting OIDC login flow",
		slog.String("operation", operation),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	transactionID, err := generateRandomValue(32)
	if err != nil {
		return wrapError(operation, "transaction_id_generation_failed", "could not generate transaction ID", err)
	}

	state := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier()
	pkceVerifier := oauth2.GenerateVerifier()

	transaction := AuthorizationTransaction{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: pkceVerifier,
		ExpiresAt:    time.Now().Add(c.transactionLifetime),
	}

	if err := c.store.SaveTransaction(r.Context(), transactionID, transaction); err != nil {
		c.logger.Debug("failed to persist login transaction",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return wrapError(operation, "transaction_save_failed", "could not save authorization transaction", err)
	}

	c.setCookie(w, c.transactionCookieName, transactionID, c.transactionLifetime)

	authorizationURL := c.oauth2Config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oidc.Nonce(nonce),
	)

	c.logger.Debug("redirecting to provider authorization endpoint",
		slog.String("operation", operation),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	http.Redirect(w, r, authorizationURL, http.StatusFound)
	return nil
}

func (c *Client) completeLogin(w http.ResponseWriter, r *http.Request) error {
	const operation = "auth.Client.completeLogin"

	c.logger.Debug("handling OIDC callback",
		slog.String("operation", operation),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	if authorizationError := r.URL.Query().Get("error"); authorizationError != "" {
		c.logger.Debug("provider returned authorization error",
			slog.String("operation", operation),
			slog.String("provider_error", authorizationError),
		)
		return wrapError(
			operation,
			"provider_authorization_failed",
			"identity provider rejected authorization",
			fmt.Errorf("%w: %s", ErrAuthentication, authorizationError),
		)
	}

	transactionID, err := readCookieValue(r, c.transactionCookieName)
	if err != nil {
		c.logger.Debug("missing authorization transaction cookie",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return wrapError(
			operation,
			"transaction_cookie_missing",
			"authorization transaction cookie is missing",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	defer func() {
		_ = c.store.DeleteTransaction(context.Background(), transactionID)
	}()

	transaction, err := c.store.GetTransaction(r.Context(), transactionID)
	if err != nil {
		c.logger.Debug("authorization transaction lookup failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return wrapError(
			operation,
			"transaction_not_found",
			"authorization transaction was not found",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	receivedState := r.URL.Query().Get("state")
	if receivedState == "" || !constantTimeEqual(receivedState, transaction.State) {
		c.logger.Debug("state validation failed",
			slog.String("operation", operation),
			slog.Bool("state_present", receivedState != ""),
		)
		return wrapError(operation, "invalid_state", "OAuth state did not match", ErrInvalidState)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return wrapError(operation, "missing_authorization_code", "authorization code was not returned", ErrMissingCode)
	}

	token, err := c.oauth2Config.Exchange(
		r.Context(),
		code,
		oauth2.VerifierOption(transaction.PKCEVerifier),
	)
	if err != nil {
		c.logger.Debug("authorization code exchange failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return wrapError(
			operation,
			"code_exchange_failed",
			"authorization-code exchange failed",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	rawIDToken, err := getIDToken(token)
	if err != nil {
		return wrapError(operation, "id_token_missing", "token response did not contain an ID token", err)
	}

	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return wrapError(
			operation,
			"id_token_verification_failed",
			"ID token verification failed",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	if !constantTimeEqual(idToken.Nonce, transaction.Nonce) {
		return wrapError(operation, "invalid_nonce", "ID token nonce did not match", ErrInvalidNonce)
	}

	if token.RefreshToken == "" {
		return wrapError(
			operation,
			"refresh_token_missing",
			"token response did not contain a refresh token",
			ErrMissingRefreshToken,
		)
	}

	sessionID, err := generateRandomValue(32)
	if err != nil {
		return wrapError(operation, "session_id_generation_failed", "could not generate session ID", err)
	}

	session := Session{
		Token:         token,
		RawIDToken:    rawIDToken,
		GrantedScopes: extractGrantedScopes(token, c.authorization.ScopeClaimPaths),
		ExpiresAt:     time.Now().Add(c.sessionLifetime),
	}

	if err := c.store.SaveSession(r.Context(), sessionID, session); err != nil {
		c.logger.Debug("failed to save authenticated session",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return wrapError(operation, "session_save_failed", "could not save authenticated session", err)
	}

	c.logger.Debug("OIDC login completed",
		slog.String("operation", operation),
		slog.Int("granted_scope_count", len(session.GrantedScopes)),
	)

	c.clearCookie(w, c.transactionCookieName)
	c.setCookie(w, c.sessionCookieName, sessionID, c.sessionLifetime)
	http.Redirect(w, r, c.loginSuccessURL, http.StatusFound)
	return nil
}

func (c *Client) logout(w http.ResponseWriter, r *http.Request) error {
	const operation = "auth.Client.logout"

	c.logger.Debug("processing logout",
		slog.String("operation", operation),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	sessionID, err := readCookieValue(r, c.sessionCookieName)
	if err == nil {
		if deleteErr := c.store.DeleteSession(r.Context(), sessionID); deleteErr != nil {
			c.logger.Debug("failed to delete session during logout",
				slog.String("operation", operation),
				slog.String("error", deleteErr.Error()),
			)
			return wrapError(operation, "session_delete_failed", "could not delete session", deleteErr)
		}

		c.logger.Debug("session deleted during logout",
			slog.String("operation", operation),
		)
	}

	c.clearCookie(w, c.sessionCookieName)
	return nil
}

func (c *Client) setCookie(w http.ResponseWriter, name, value string, lifetime time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(lifetime.Seconds()),
		Expires:  time.Now().Add(lifetime),
		HttpOnly: true,
		Secure:   c.cookieSecure,
		SameSite: c.cookieSameSite,
	})
}

func (c *Client) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   c.cookieSecure,
		SameSite: c.cookieSameSite,
	})
}

func readCookieValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", fmt.Errorf("cookie %q is empty", name)
	}
	return cookie.Value, nil
}

func getIDToken(token *oauth2.Token) (string, error) {
	if token == nil {
		return "", ErrMissingIDToken
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", ErrMissingIDToken
	}
	return rawIDToken, nil
}

func generateRandomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
