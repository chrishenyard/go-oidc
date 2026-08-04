package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/chrishenyard/go-oidc"
	"golang.org/x/net/html"
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
		"http://127.0.0.1:8081/login",
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

const (
	testUsername = "alice"
	testPassword = "password"

	testSessionCookieName = "test_oidc_session"
)

func TestCallback_CreatesAuthenticatedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
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
			SessionCookieName:     testSessionCookieName,

			TransactionLifetime: 5 * time.Minute,
			SessionLifetime:     8 * time.Hour,

			CookieSecure:   false,
			CookieSameSite: http.SameSiteLaxMode,

			LoginSuccessURL: "/dashboard",
		},
	)
	if err != nil {
		t.Fatalf("create authentication client: %v", err)
	}

	/*
		Step 1: Call the package's login handler.

		This creates the server-side authorization transaction,
		sets the transaction cookie, and redirects to Keycloak.
	*/
	loginRequest := httptest.NewRequest(
		http.MethodGet,
		"http://127.0.0.1:8081/login",
		nil,
	)

	loginResponse := httptest.NewRecorder()

	client.LoginHandler().ServeHTTP(
		loginResponse,
		loginRequest,
	)

	loginResult := loginResponse.Result()
	defer loginResult.Body.Close()

	if loginResult.StatusCode != http.StatusFound {
		t.Fatalf(
			"expected login status %d, got %d",
			http.StatusFound,
			loginResult.StatusCode,
		)
	}

	authorizationURL := loginResult.Header.Get("Location")
	if authorizationURL == "" {
		t.Fatal("expected authorization redirect URL")
	}

	transactionCookie := findCookie(
		loginResult.Cookies(),
		testTransactionCookieName,
	)
	if transactionCookie == nil {
		t.Fatalf(
			"expected transaction cookie %q",
			testTransactionCookieName,
		)
	}

	transactionID := transactionCookie.Value
	if transactionID == "" {
		t.Fatal("expected nonempty transaction ID")
	}

	/*
		Step 2: Create a browser-like HTTP client.

		The cookie jar preserves Keycloak's own authentication-session
		cookies between retrieving and submitting the login form.
	*/
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create HTTP cookie jar: %v", err)
	}

	browser := &http.Client{
		Jar: jar,

		CheckRedirect: func(
			request *http.Request,
			via []*http.Request,
		) error {
			/*
				Allow redirects within Keycloak, but stop when
				Keycloak redirects back to this application.
			*/
			if request.URL.Host == "127.0.0.1:8081" {
				return http.ErrUseLastResponse
			}

			if len(via) >= 10 {
				return errors.New("too many redirects")
			}

			return nil
		},

		Timeout: 15 * time.Second,
	}

	/*
		Step 3: Retrieve Keycloak's login page.
	*/
	keycloakLoginResponse, err := browser.Get(authorizationURL)
	if err != nil {
		t.Fatalf(
			"request Keycloak login page: %v",
			err,
		)
	}
	defer keycloakLoginResponse.Body.Close()

	if keycloakLoginResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(
			io.LimitReader(
				keycloakLoginResponse.Body,
				4096,
			),
		)

		t.Fatalf(
			"expected Keycloak login status %d, got %d: %s",
			http.StatusOK,
			keycloakLoginResponse.StatusCode,
			string(body),
		)
	}

	loginFormAction, err := findLoginFormAction(
		keycloakLoginResponse.Body,
	)
	if err != nil {
		t.Fatalf(
			"find Keycloak login form action: %v",
			err,
		)
	}

	/*
		Keycloak normally returns an absolute action URL, but resolving
		it against the login page URL also handles a relative action.
	*/
	loginPageURL := keycloakLoginResponse.Request.URL

	actionURL, err := loginPageURL.Parse(loginFormAction)
	if err != nil {
		t.Fatalf(
			"resolve Keycloak login form action %q: %v",
			loginFormAction,
			err,
		)
	}

	/*
		Step 4: Submit the Keycloak login form.
	*/
	form := url.Values{
		"username": {testUsername},
		"password": {testPassword},
	}

	formRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		actionURL.String(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("create Keycloak login request: %v", err)
	}

	formRequest.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)

	keycloakCallbackResponse, err := browser.Do(formRequest)
	if err != nil {
		t.Fatalf(
			"submit Keycloak login form: %v",
			err,
		)
	}
	defer keycloakCallbackResponse.Body.Close()

	if keycloakCallbackResponse.StatusCode != http.StatusFound {
		respDump, err := httputil.DumpResponse(keycloakCallbackResponse, true)
		if err != nil {
			t.Fatalf("dump Keycloak callback response: %v", err)
		}

		t.Fatalf(
			"expected Keycloak callback redirect status %d, got %d: %s",
			http.StatusFound,
			keycloakCallbackResponse.StatusCode,
			respDump,
		)
	}

	callbackURL := keycloakCallbackResponse.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("expected Keycloak callback Location header")
	}

	parsedCallbackURL, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf(
			"parse callback URL %q: %v",
			callbackURL,
			err,
		)
	}

	if parsedCallbackURL.Scheme != "http" {
		t.Errorf(
			"expected callback scheme %q, got %q",
			"http",
			parsedCallbackURL.Scheme,
		)
	}

	if parsedCallbackURL.Host != "127.0.0.1:8081" {
		t.Errorf(
			"expected callback host %q, got %q",
			"127.0.0.1:8081",
			parsedCallbackURL.Host,
		)
	}

	if parsedCallbackURL.Path != "/callback" {
		t.Errorf(
			"expected callback path %q, got %q",
			"/callback",
			parsedCallbackURL.Path,
		)
	}

	if parsedCallbackURL.Query().Get("code") == "" {
		t.Fatal("expected callback authorization code")
	}

	if parsedCallbackURL.Query().Get("state") == "" {
		t.Fatal("expected callback state")
	}

	if authorizationError :=
		parsedCallbackURL.Query().Get("error"); authorizationError != "" {

		t.Fatalf(
			"Keycloak returned authorization error %q: %s",
			authorizationError,
			parsedCallbackURL.Query().Get(
				"error_description",
			),
		)
	}

	/*
		Step 5: Send Keycloak's callback to the package callback handler.

		The application transaction cookie must be included because it
		links the callback to the state, nonce, and PKCE verifier that
		were stored during /login.
	*/
	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		callbackURL,
		nil,
	)

	callbackRequest.AddCookie(transactionCookie)

	callbackResponse := httptest.NewRecorder()

	client.CallbackHandler().ServeHTTP(
		callbackResponse,
		callbackRequest,
	)

	callbackResult := callbackResponse.Result()
	defer callbackResult.Body.Close()

	if callbackResult.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResult.Body)

		t.Fatalf(
			"expected callback status %d, got %d: %s",
			http.StatusFound,
			callbackResult.StatusCode,
			string(body),
		)
	}

	if location := callbackResult.Header.Get("Location"); location != "/dashboard" {

		t.Errorf(
			"expected success redirect %q, got %q",
			"/dashboard",
			location,
		)
	}

	/*
		Step 6: Verify that an opaque application session cookie
		was issued.
	*/
	sessionCookie := findCookie(
		callbackResult.Cookies(),
		testSessionCookieName,
	)
	if sessionCookie == nil {
		t.Fatalf(
			"expected session cookie %q",
			testSessionCookieName,
		)
	}

	if sessionCookie.Value == "" {
		t.Fatal("expected nonempty session cookie value")
	}

	if !sessionCookie.HttpOnly {
		t.Error("expected session cookie to be HttpOnly")
	}

	if sessionCookie.Secure {
		t.Error(
			"expected session cookie Secure=false in HTTP test",
		)
	}

	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf(
			"expected session cookie SameSite %v, got %v",
			http.SameSiteLaxMode,
			sessionCookie.SameSite,
		)
	}

	if sessionCookie.Path != "/" {
		t.Errorf(
			"expected session cookie path %q, got %q",
			"/",
			sessionCookie.Path,
		)
	}

	/*
		Step 7: Retrieve and verify the server-side session.
	*/
	session, err := store.GetSession(
		ctx,
		sessionCookie.Value,
	)
	if err != nil {
		t.Fatalf(
			"retrieve authenticated session: %v",
			err,
		)
	}

	if session.Token == nil {
		t.Fatal("expected session OAuth token")
	}

	if session.Token.AccessToken == "" {
		t.Error("expected access token")
	}

	if session.Token.RefreshToken == "" {
		t.Error("expected refresh token")
	}

	if session.Token.TokenType == "" {
		t.Error("expected token type")
	}

	if session.Token.Expiry.IsZero() {
		t.Error("expected access-token expiration")
	}

	if !session.Token.Expiry.After(time.Now()) {
		t.Errorf(
			"expected access token to expire in the future, got %s",
			session.Token.Expiry,
		)
	}

	if session.RawIDToken == "" {
		t.Error("expected raw ID token")
	}

	if session.ExpiresAt.IsZero() {
		t.Error("expected application session expiration")
	}

	if !session.ExpiresAt.After(time.Now()) {
		t.Errorf(
			"expected application session expiration in the future, got %s",
			session.ExpiresAt,
		)
	}

	/*
		The browser cookie should contain only the random session ID.
	*/
	if strings.Contains(
		sessionCookie.Value,
		session.Token.AccessToken,
	) {
		t.Error("session cookie contains access token")
	}

	if strings.Contains(
		sessionCookie.Value,
		session.Token.RefreshToken,
	) {
		t.Error("session cookie contains refresh token")
	}

	if strings.Contains(
		sessionCookie.Value,
		session.RawIDToken,
	) {
		t.Error("session cookie contains ID token")
	}

	/*
		The one-time authorization transaction must have been consumed.
	*/
	_, err = store.GetTransaction(
		ctx,
		transactionID,
	)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf(
			"expected authorization transaction to be deleted, got %v",
			err,
		)
	}

	/*
		The callback should also expire the browser's transaction cookie.
	*/
	clearedTransactionCookie := findCookie(
		callbackResult.Cookies(),
		testTransactionCookieName,
	)
	if clearedTransactionCookie == nil {
		t.Fatalf(
			"expected callback to clear transaction cookie %q",
			testTransactionCookieName,
		)
	}

	if clearedTransactionCookie.MaxAge >= 0 {
		t.Errorf(
			"expected cleared transaction cookie MaxAge below zero, got %d",
			clearedTransactionCookie.MaxAge,
		)
	}
}

func findLoginFormAction(
	reader io.Reader,
) (string, error) {
	document, err := html.Parse(reader)
	if err != nil {
		return "", fmt.Errorf(
			"parse Keycloak login page: %w",
			err,
		)
	}

	var walk func(node *html.Node) string

	walk = func(node *html.Node) string {
		if node.Type == html.ElementNode &&
			node.Data == "form" {

			var (
				id     string
				action string
			)

			for _, attribute := range node.Attr {
				switch attribute.Key {
				case "id":
					id = attribute.Val

				case "action":
					action = attribute.Val
				}
			}

			/*
				Keycloak's standard login theme identifies the
				credential form with this ID.
			*/
			if id == "kc-form-login" && action != "" {
				return action
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {

			if action := walk(child); action != "" {
				return action
			}
		}

		return ""
	}

	action := walk(document)
	if action == "" {
		return "", errors.New(
			"Keycloak login form was not found",
		)
	}

	return action, nil
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
