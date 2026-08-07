package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Principal is the package's provider-independent representation of an
// authenticated user and the authorization information granted to the client.
type Principal struct {
	Subject           string
	Email             string
	Name              string
	PreferredUsername string

	Scopes []string
	Roles  []string

	// Claims contains the merged claims obtained from the verified ID token and,
	// when enabled, the OIDC UserInfo endpoint. Applications should normally use
	// the normalized fields above.
	Claims map[string]any
}

func (p Principal) HasScope(scope string) bool {
	return slices.Contains(p.Scopes, scope)
}

func (p Principal) HasRole(role string) bool {
	return slices.Contains(p.Roles, role)
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// Claims is retained as a compatibility alias. New code should use Principal.
type Claims = Principal

// ClaimsFromContext is retained for compatibility. New code should use
// PrincipalFromContext.
func ClaimsFromContext(ctx context.Context) (Principal, bool) {
	return PrincipalFromContext(ctx)
}

func (c *Client) buildPrincipal(
	ctx context.Context,
	idToken *oidc.IDToken,
	session Session,
) (Principal, error) {
	const operation = "auth.Client.buildPrincipal"

	claims, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return Principal{}, wrapError(
			operation,
			"claims_decoding_failed",
			"could not decode verified ID-token claims",
			err,
		)
	}

	if c.authorization.LoadUserInfo {
		userInfoClaims, err := c.loadUserInfoClaims(ctx, session.Token)
		if err != nil {
			return Principal{}, wrapError(
				operation,
				"userinfo_failed",
				"could not load UserInfo claims",
				err,
			)
		}
		mergeClaims(claims, userInfoClaims)
	}

	roles := extractClaimValues(
		claims,
		c.authorization.RoleClaimPaths,
		c.oauth2Config.ClientID,
	)

	scopes := append([]string(nil), session.GrantedScopes...)
	scopes = append(
		scopes,
		extractClaimValues(
			claims,
			c.authorization.ScopeClaimPaths,
			c.oauth2Config.ClientID,
		)...,
	)

	return Principal{
		Subject:           stringClaim(claims, "sub"),
		Email:             stringClaim(claims, "email"),
		Name:              stringClaim(claims, "name"),
		PreferredUsername: stringClaim(claims, "preferred_username"),
		Scopes:            uniqueStrings(scopes),
		Roles:             uniqueStrings(roles),
		Claims:            cloneClaims(claims),
	}, nil
}

func decodeIDTokenClaims(idToken *oidc.IDToken) (map[string]any, error) {
	if idToken == nil {
		return nil, errors.New("ID token is nil")
	}

	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode ID token claims: %w", err)
	}

	return claims, nil
}

func (c *Client) loadUserInfoClaims(ctx context.Context, token *oauth2.Token) (map[string]any, error) {
	if token == nil {
		return nil, errors.New("OAuth token is nil")
	}

	userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("request UserInfo: %w", err)
	}

	claims := make(map[string]any)
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode UserInfo claims: %w", err)
	}

	return claims, nil
}

func extractGrantedScopes(token *oauth2.Token, claimNames []string) []string {
	if token == nil {
		return nil
	}

	var scopes []string
	for _, name := range claimNames {
		// Nested paths do not apply to token response extras. Only inspect the
		// top-level response member when a simple claim name was configured.
		if strings.Contains(name, ".") {
			continue
		}
		scopes = append(scopes, normalizeStringValues(token.Extra(name))...)
	}

	return uniqueStrings(scopes)
}

func extractClaimValues(claims map[string]any, paths []string, clientID string) []string {
	var values []string

	for _, path := range paths {
		value, found := claimValueAtPath(claims, path, clientID)
		if !found {
			continue
		}
		values = append(values, normalizeStringValues(value)...)
	}

	return uniqueStrings(values)
}

func claimValueAtPath(claims map[string]any, path, clientID string) (any, bool) {
	path = strings.TrimSpace(strings.ReplaceAll(path, "{client_id}", clientID))
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")
	var current any = claims

	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}

	return current, true
}

func normalizeStringValues(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return splitClaimString(typed)
	case []string:
		return cleanStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if ok {
				values = append(values, splitClaimString(text)...)
			}
		}
		return cleanStrings(values)
	default:
		return nil
	}
}

func splitClaimString(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
}

func cleanStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range cleanStrings(values) {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	slices.Sort(result)
	return result
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func mergeClaims(destination, source map[string]any) {
	for key, sourceValue := range source {
		sourceObject, sourceIsObject := sourceValue.(map[string]any)
		destinationObject, destinationIsObject := destination[key].(map[string]any)

		if sourceIsObject && destinationIsObject {
			mergeClaims(destinationObject, sourceObject)
			continue
		}

		destination[key] = sourceValue
	}
}

func cloneClaims(claims map[string]any) map[string]any {
	copyClaims := make(map[string]any, len(claims))
	for key, value := range claims {
		switch typed := value.(type) {
		case map[string]any:
			copyClaims[key] = cloneClaims(typed)
		case []any:
			copyClaims[key] = append([]any(nil), typed...)
		case []string:
			copyClaims[key] = append([]string(nil), typed...)
		default:
			copyClaims[key] = value
		}
	}
	return copyClaims
}
