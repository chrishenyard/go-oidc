package auth

import (
	"context"
	"fmt"
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
		principal, err := c.authenticateRequest(w, r)
		if err != nil {
			c.errorHandler(w, r, err)
			return
		}

		if authorize != nil {
			if err := authorize(principal); err != nil {
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

		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *Client) authenticateRequest(w http.ResponseWriter, r *http.Request) (Principal, error) {
	const operation = "auth.Client.authenticateRequest"

	sessionID, err := readCookieValue(r, c.sessionCookieName)
	if err != nil {
		return Principal{}, wrapError(
			operation,
			"session_cookie_missing",
			"session cookie is missing",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	session, err := c.store.GetSession(r.Context(), sessionID)
	if err != nil {
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
		_ = c.store.DeleteSession(context.Background(), sessionID)
		c.clearCookie(w, c.sessionCookieName)
		return Principal{}, err
	}

	if sessionChanged(session, refreshedSession) {
		if err := c.store.SaveSession(r.Context(), sessionID, refreshedSession); err != nil {
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
		return Principal{}, err
	}

	return principal, nil
}

func (c *Client) refreshSession(ctx context.Context, session Session) (Session, error) {
	const operation = "auth.Client.refreshSession"

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
		return updated, nil
	}

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
		return Session{}, wrapError(
			operation,
			"refreshed_id_token_invalid",
			"refreshed ID token did not pass verification",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	updated.RawIDToken = rawIDToken
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
