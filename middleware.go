package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// AuthorizeFunc performs application-specific authorization against a
// normalized Principal.
type AuthorizeFunc func(principal Principal) error

// RequireAuthentication requires a valid authenticated session without
// imposing a role or scope requirement.
func (c *Client) RequireAuthentication(next http.Handler) http.Handler {
	return c.Middleware(nil, next)
}

// RequireRole authenticates the session and requires a normalized role.
func (c *Client) RequireRole(requiredRole string, next http.Handler) http.Handler {
	return c.Middleware(
		func(principal Principal) error {
			if !principal.HasRole(requiredRole) {
				return fmt.Errorf("%w: required role %q", ErrInsufficientRole, requiredRole)
			}
			return nil
		},
		next,
	)
}

// RequireScope authenticates the session and requires a granted OAuth scope.
func (c *Client) RequireScope(requiredScope string, next http.Handler) http.Handler {
	return c.Middleware(
		func(principal Principal) error {
			if !principal.HasScope(requiredScope) {
				return fmt.Errorf("%w: required scope %q", ErrInsufficientScope, requiredScope)
			}
			return nil
		},
		next,
	)
}

// Middleware validates the session, refreshes the OAuth token when needed,
// builds a provider-independent Principal, and optionally invokes authorize.
func (c *Client) Middleware(authorize AuthorizeFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.logger.Debug("auth middleware started",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		)

		principal, err := c.authenticateRequest(w, r)
		if err != nil {
			c.logger.Debug("request authentication failed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("error", err.Error()),
			)
			c.errorHandler(w, r, err)
			return
		}

		if authorize != nil {
			if err := authorize(principal); err != nil {
				c.logger.Debug("request authorization failed",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("subject", principal.Subject),
					slog.String("error", err.Error()),
				)
				c.errorHandler(
					w,
					r,
					wrapError(
						"auth.Client.Middleware",
						"authorization_denied",
						"request authorization failed",
						fmt.Errorf("%w: %v", ErrAuthorization, err),
					),
				)
				return
			}
		}

		c.logger.Debug("auth middleware passed",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("subject", principal.Subject),
		)

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *Client) authenticateRequest(w http.ResponseWriter, r *http.Request) (Principal, error) {
	const operation = "auth.Client.authenticateRequest"

	c.logger.Debug("authenticating request",
		slog.String("operation", operation),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	)

	sessionID, err := readCookieValue(r, c.sessionCookieName)
	if err != nil {
		c.logger.Debug("session cookie not found",
			slog.String("operation", operation),
			slog.String("cookie_name", c.sessionCookieName),
			slog.String("error", err.Error()),
		)
		return Principal{}, wrapError(
			operation,
			"session_cookie_missing",
			"session cookie is missing",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	session, err := c.store.GetSession(r.Context(), sessionID)
	if err != nil {
		c.logger.Debug("session lookup failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		c.clearCookie(w, c.sessionCookieName)
		return Principal{}, wrapError(
			operation,
			"session_not_found",
			"authenticated session was not found",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	refreshedSession, err := c.refreshSession(r.Context(), session)
	if err != nil {
		c.logger.Debug("session refresh failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		_ = c.store.DeleteSession(context.Background(), sessionID)
		c.clearCookie(w, c.sessionCookieName)
		return Principal{}, err
	}

	if sessionChanged(session, refreshedSession) {
		c.logger.Debug("session changed after refresh",
			slog.String("operation", operation),
		)
		if err := c.store.SaveSession(r.Context(), sessionID, refreshedSession); err != nil {
			c.logger.Debug("failed to persist refreshed session",
				slog.String("operation", operation),
				slog.String("error", err.Error()),
			)
			return Principal{}, wrapError(
				operation,
				"session_update_failed",
				"could not update refreshed session",
				err,
			)
		}
	}

	idToken, err := c.verifier.Verify(r.Context(), refreshedSession.RawIDToken)
	if err != nil {
		c.logger.Debug("id token verification failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		_ = c.store.DeleteSession(context.Background(), sessionID)
		c.clearCookie(w, c.sessionCookieName)
		return Principal{}, wrapError(
			operation,
			"id_token_verification_failed",
			"ID token is invalid or expired",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	principal, err := c.buildPrincipal(r.Context(), idToken, refreshedSession)
	if err != nil {
		c.logger.Debug("principal construction failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return Principal{}, err
	}

	c.logger.Debug("request authenticated",
		slog.String("operation", operation),
		slog.String("subject", principal.Subject),
		slog.Int("role_count", len(principal.Roles)),
		slog.Int("scope_count", len(principal.Scopes)),
	)

	return principal, nil
}

func (c *Client) refreshSession(ctx context.Context, session Session) (Session, error) {
	const operation = "auth.Client.refreshSession"

	c.logger.Debug("refreshing OAuth token",
		slog.String("operation", operation),
		slog.Bool("token_present", session.Token != nil),
	)

	if session.Token == nil {
		return Session{}, wrapError(
			operation,
			"token_missing",
			"session does not contain an OAuth token",
			ErrAuthentication,
		)
	}

	previousToken := session.Token
	currentToken, err := c.oauth2Config.TokenSource(ctx, previousToken).Token()
	if err != nil {
		c.logger.Debug("OAuth token refresh failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return Session{}, wrapError(
			operation,
			"token_refresh_failed",
			"OAuth token could not be refreshed",
			fmt.Errorf("%w: %v", ErrTokenRefresh, err),
		)
	}

	updated := session
	updated.Token = currentToken

	if scopes := extractGrantedScopes(currentToken, c.authorization.ScopeClaimPaths); len(scopes) > 0 {
		updated.GrantedScopes = scopes
	}

	accessTokenChanged := currentToken.AccessToken != previousToken.AccessToken
	if !accessTokenChanged {
		c.logger.Debug("existing access token is still valid",
			slog.String("operation", operation),
		)
		return updated, nil
	}

	c.logger.Debug("access token changed, validating refreshed ID token",
		slog.String("operation", operation),
	)

	rawIDToken, err := getIDToken(currentToken)
	if err != nil {
		return Session{}, wrapError(
			operation,
			"refreshed_id_token_missing",
			"refresh response did not contain a new ID token",
			err,
		)
	}

	if _, err := c.verifier.Verify(ctx, rawIDToken); err != nil {
		c.logger.Debug("refreshed ID token verification failed",
			slog.String("operation", operation),
			slog.String("error", err.Error()),
		)
		return Session{}, wrapError(
			operation,
			"refreshed_id_token_invalid",
			"refreshed ID token did not pass verification",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	updated.RawIDToken = rawIDToken
	c.logger.Debug("session refresh completed",
		slog.String("operation", operation),
		slog.Int("granted_scope_count", len(updated.GrantedScopes)),
	)
	return updated, nil
}

func sessionChanged(before, after Session) bool {
	if before.RawIDToken != after.RawIDToken {
		return true
	}

	if !stringSlicesEqual(before.GrantedScopes, after.GrantedScopes) {
		return true
	}

	if before.Token == nil || after.Token == nil {
		return before.Token != after.Token
	}

	return before.Token.AccessToken != after.Token.AccessToken ||
		before.Token.RefreshToken != after.Token.RefreshToken ||
		!before.Token.Expiry.Equal(after.Token.Expiry)
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
