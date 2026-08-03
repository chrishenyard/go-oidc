package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/chrishenyard/go-oidc"
)

const testTransactionCookieName = "test_oidc_transaction"

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

func TestLoginHandler_RedirectsToKeycloak(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancel()

	store := auth.NewMemoryStore()

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

			Store: store,

			TransactionCookieName: testTransactionCookieName,
			TransactionLifetime:   5 * time.Minute,
			SessionLifetime:       8 * time.Hour,

			CookieSecure:   false,
			CookieSameSite: http.SameSiteLaxMode,

			LoginSuccessURL: "/dashboard",
		},
	)
	if err != nil {
		t.Fatalf("create authentication client: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"http://localhost:8081/login",
		nil,
	)

	response := httptest.NewRecorder()

	client.LoginHandler().ServeHTTP(response, request)

	result := response.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusFound,
			result.StatusCode,
		)
	}

	location := result.Header.Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	authorizationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf(
			"parse authorization URL %q: %v",
			location,
			err,
		)
	}

	expectedIssuerURL, err := url.Parse(
		integrationEnvironment.IssuerURL,
	)
	if err != nil {
		t.Fatalf(
			"parse issuer URL %q: %v",
			integrationEnvironment.IssuerURL,
			err,
		)
	}

	expectedAuthorizationPath :=
		expectedIssuerURL.Path +
			"/protocol/openid-connect/auth"

	if authorizationURL.Scheme != expectedIssuerURL.Scheme {
		t.Errorf(
			"expected authorization URL scheme %q, got %q",
			expectedIssuerURL.Scheme,
			authorizationURL.Scheme,
		)
	}

	if authorizationURL.Host != expectedIssuerURL.Host {
		t.Errorf(
			"expected authorization URL host %q, got %q",
			expectedIssuerURL.Host,
			authorizationURL.Host,
		)
	}

	if authorizationURL.Path != expectedAuthorizationPath {
		t.Errorf(
			"expected authorization URL path %q, got %q",
			expectedAuthorizationPath,
			authorizationURL.Path,
		)
	}

	query := authorizationURL.Query()

	assertQueryValue(
		t,
		query,
		"client_id",
		testClientID,
	)

	assertQueryValue(
		t,
		query,
		"redirect_uri",
		testRedirectURL,
	)

	assertQueryValue(
		t,
		query,
		"response_type",
		"code",
	)

	assertQueryValue(
		t,
		query,
		"code_challenge_method",
		"S256",
	)

	state := query.Get("state")
	if state == "" {
		t.Error("expected nonempty state parameter")
	}

	nonce := query.Get("nonce")
	if nonce == "" {
		t.Error("expected nonempty nonce parameter")
	}

	codeChallenge := query.Get("code_challenge")
	if codeChallenge == "" {
		t.Error("expected nonempty code_challenge parameter")
	}

	assertScopes(
		t,
		query.Get("scope"),
		"openid",
		"profile",
		"email",
		"roles",
	)

	transactionCookie := findCookie(
		result.Cookies(),
		testTransactionCookieName,
	)
	if transactionCookie == nil {
		t.Fatalf(
			"expected cookie %q",
			testTransactionCookieName,
		)
	}

	if transactionCookie.Value == "" {
		t.Fatal("expected nonempty transaction cookie value")
	}

	if !transactionCookie.HttpOnly {
		t.Error("expected transaction cookie to be HttpOnly")
	}

	if transactionCookie.Secure {
		t.Error(
			"expected transaction cookie Secure to be false in HTTP test",
		)
	}

	if transactionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf(
			"expected SameSite %v, got %v",
			http.SameSiteLaxMode,
			transactionCookie.SameSite,
		)
	}

	if transactionCookie.Path != "/" {
		t.Errorf(
			"expected cookie path %q, got %q",
			"/",
			transactionCookie.Path,
		)
	}

	if transactionCookie.MaxAge <= 0 {
		t.Errorf(
			"expected positive cookie MaxAge, got %d",
			transactionCookie.MaxAge,
		)
	}

	transaction, err := store.GetTransaction(
		ctx,
		transactionCookie.Value,
	)
	if err != nil {
		t.Fatalf(
			"retrieve stored authorization transaction: %v",
			err,
		)
	}

	if transaction.State == "" {
		t.Error("expected stored state")
	}

	if transaction.State != state {
		t.Errorf(
			"stored state does not match redirect state",
		)
	}

	if transaction.Nonce == "" {
		t.Error("expected stored nonce")
	}

	if transaction.Nonce != nonce {
		t.Errorf(
			"stored nonce does not match redirect nonce",
		)
	}

	if transaction.PKCEVerifier == "" {
		t.Error("expected stored PKCE verifier")
	}

	if transaction.ExpiresAt.IsZero() {
		t.Error("expected transaction expiration time")
	}

	if !transaction.ExpiresAt.After(time.Now()) {
		t.Errorf(
			"expected transaction expiration in the future, got %s",
			transaction.ExpiresAt,
		)
	}

	/*
		The browser cookie should contain only the opaque transaction ID.
		Sensitive transaction values must remain in server-side storage.
	*/
	if strings.Contains(
		transactionCookie.Value,
		transaction.State,
	) {
		t.Error("transaction cookie contains OAuth state")
	}

	if strings.Contains(
		transactionCookie.Value,
		transaction.Nonce,
	) {
		t.Error("transaction cookie contains OIDC nonce")
	}

	if strings.Contains(
		transactionCookie.Value,
		transaction.PKCEVerifier,
	) {
		t.Error("transaction cookie contains PKCE verifier")
	}
}

func assertQueryValue(
	t *testing.T,
	query url.Values,
	name string,
	expected string,
) {
	t.Helper()

	actual := query.Get(name)

	if actual != expected {
		t.Errorf(
			"expected query parameter %q to equal %q, got %q",
			name,
			expected,
			actual,
		)
	}
}

func assertScopes(
	t *testing.T,
	rawScopes string,
	expectedScopes ...string,
) {
	t.Helper()

	if rawScopes == "" {
		t.Fatal("expected nonempty scope parameter")
	}

	actualScopes := strings.Fields(rawScopes)

	for _, expected := range expectedScopes {
		if !contains(actualScopes, expected) {
			t.Errorf(
				"expected scope %q in %q",
				expected,
				rawScopes,
			)
		}
	}
}

func contains(
	values []string,
	expected string,
) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func findCookie(
	cookies []*http.Cookie,
	name string,
) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}
