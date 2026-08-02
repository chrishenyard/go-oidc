package auth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
)

type Claims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Roles   []string `json:"roles"`
}

type claimsContextKey struct{}

// ClaimsFromContext retrieves verified claims inserted by Middleware.
func ClaimsFromContext(
	ctx context.Context,
) (Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(Claims)
	return claims, ok
}

// RequireRole authenticates the session and requires a particular role.
func (c *Client) RequireRole(
	requiredRole string,
	next http.Handler,
) http.Handler {
	return c.Middleware(
		func(claims Claims) error {
			if !slices.Contains(claims.Roles, requiredRole) {
				return ErrInsufficientRole
			}

			return nil
		},
		next,
	)
}

// RequireAuthentication requires a valid authenticated session without
// imposing a role requirement.
func (c *Client) RequireAuthentication(
	next http.Handler,
) http.Handler {
	return c.Middleware(nil, next)
}

type AuthorizeFunc func(claims Claims) error

// Middleware validates the session, refreshes the OAuth token when needed,
// verifies the current ID token, and optionally invokes authorize.
func (c *Client) Middleware(
	authorize AuthorizeFunc,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		claims, err := c.authenticateRequest(w, r)
		if err != nil {
			c.errorHandler(w, r, err)
			return
		}

		if authorize != nil {
			if err := authorize(claims); err != nil {
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

		ctx := context.WithValue(
			r.Context(),
			claimsContextKey{},
			claims,
		)

		next.ServeHTTP(
			w,
			r.WithContext(ctx),
		)
	})
}

func (c *Client) authenticateRequest(
	w http.ResponseWriter,
	r *http.Request,
) (Claims, error) {
	const operation = "auth.Client.authenticateRequest"

	sessionID, err := readCookieValue(
		r,
		c.sessionCookieName,
	)
	if err != nil {
		return Claims{}, wrapError(
			operation,
			"session_cookie_missing",
			"session cookie is missing",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	session, err := c.store.GetSession(
		r.Context(),
		sessionID,
	)
	if err != nil {
		c.clearCookie(w, c.sessionCookieName)

		return Claims{}, wrapError(
			operation,
			"session_not_found",
			"authenticated session was not found",
			fmt.Errorf("%w: %v", ErrSessionNotFound, err),
		)
	}

	refreshedSession, err := c.refreshSession(
		r.Context(),
		session,
	)
	if err != nil {
		_ = c.store.DeleteSession(
			context.Background(),
			sessionID,
		)

		c.clearCookie(w, c.sessionCookieName)

		return Claims{}, err
	}

	if sessionChanged(session, refreshedSession) {
		if err := c.store.SaveSession(
			r.Context(),
			sessionID,
			refreshedSession,
		); err != nil {
			return Claims{}, wrapError(
				operation,
				"session_update_failed",
				"could not update refreshed session",
				err,
			)
		}
	}

	idToken, err := c.verifier.Verify(
		r.Context(),
		refreshedSession.RawIDToken,
	)
	if err != nil {
		_ = c.store.DeleteSession(
			context.Background(),
			sessionID,
		)

		c.clearCookie(w, c.sessionCookieName)

		return Claims{}, wrapError(
			operation,
			"id_token_verification_failed",
			"ID token is invalid or expired",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return Claims{}, wrapError(
			operation,
			"claims_decoding_failed",
			"could not decode ID token claims",
			err,
		)
	}

	return claims, nil
}

func (c *Client) refreshSession(
	ctx context.Context,
	session Session,
) (Session, error) {
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

	tokenSource := c.oauth2Config.TokenSource(
		ctx,
		previousToken,
	)

	currentToken, err := tokenSource.Token()
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

	accessTokenChanged :=
		currentToken.AccessToken != previousToken.AccessToken

	if !accessTokenChanged {
		return updated, nil
	}

	/*
		A provider can return a new ID token in the refresh response.
		Because authorization is based on ID-token claims, require a new
		ID token whenever the access token has been refreshed.
	*/
	rawIDToken, err := getIDToken(currentToken)
	if err != nil {
		return Session{}, wrapError(
			operation,
			"refreshed_id_token_missing",
			"refresh response did not contain a new ID token",
			err,
		)
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Session{}, wrapError(
			operation,
			"refreshed_id_token_invalid",
			"refreshed ID token did not pass verification",
			fmt.Errorf("%w: %v", ErrAuthentication, err),
		)
	}

	// A nonce is required during the initial authorization response.
	// Refreshed ID tokens do not need to repeat that original nonce.
	_ = idToken

	updated.RawIDToken = rawIDToken

	return updated, nil
}

func sessionChanged(
	before Session,
	after Session,
) bool {
	if before.RawIDToken != after.RawIDToken {
		return true
	}

	if before.Token == nil || after.Token == nil {
		return before.Token != after.Token
	}

	return before.Token.AccessToken != after.Token.AccessToken ||
		before.Token.RefreshToken != after.Token.RefreshToken ||
		!before.Token.Expiry.Equal(after.Token.Expiry)
}
