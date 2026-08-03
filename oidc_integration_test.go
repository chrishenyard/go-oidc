package auth_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/chrishenyard/go-oidc"
)

func TestNew_WithValidKeycloakConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancel()

	client, err := auth.New(
		ctx,
		auth.Config{
			IssuerURL: integrationEnvironment.IssuerURL,

			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			RedirectURL:  testRedirectURL,

			Scopes: []string{
				"openid",
				"profile",
				"email",
				"roles",
			},

			Store: auth.NewMemoryStore(),

			CookieSecure: false,

			TransactionLifetime: 5 * time.Minute,
			SessionLifetime:     8 * time.Hour,

			LoginSuccessURL: "/dashboard",
		},
	)
	if err != nil {
		t.Fatalf(
			"create authentication client using issuer %q: %v",
			integrationEnvironment.IssuerURL,
			err,
		)
	}

	if client == nil {
		t.Fatal("expected auth.New to return a non-nil client")
	}
}
