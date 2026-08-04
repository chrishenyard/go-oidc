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

const (
	testApplicationURL = "http://127.0.0.1:8081"

	testTransactionCookieName = "test_oidc_transaction"
	testSessionCookieName     = "test_oidc_session"

	testUsername = "alice"
	testPassword = "password"
	testEmail    = "alice@example.com"
)

type authenticatedTestSession struct {
	SessionCookie    *http.Cookie
	Session          auth.Session
	TransactionID    string
	CallbackResult   *http.Response
	CallbackCookies  []*http.Cookie
	CallbackLocation string
}

func newIntegrationAuthClient(
	t *testing.T,
	ctx context.Context,
	store auth.Store,
) *auth.Client {
	t.Helper()

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
		t.Fatalf(
			"create integration auth client: %v",
			err,
		)
	}

	return client
}

func authenticateTestUser(
	t *testing.T,
	ctx context.Context,
	client *auth.Client,
	store auth.Store,
	username string,
	password string,
) authenticatedTestSession {
	t.Helper()

	loginResult := executeHandler(
		t,
		client.LoginHandler(),
		http.MethodGet,
		testApplicationURL+"/login",
		nil,
	)

	assertStatus(t, loginResult, http.StatusFound)

	authorizationURL := requireHeader(
		t,
		loginResult,
		"Location",
	)

	transactionCookie := requireCookie(
		t,
		loginResult.Cookies(),
		testTransactionCookieName,
	)

	transactionID := transactionCookie.Value
	if transactionID == "" {
		t.Fatal("expected nonempty transaction ID")
	}

	browser := newKeycloakBrowser(t)

	keycloakLoginResponse, err := browser.Get(authorizationURL)
	if err != nil {
		t.Fatalf(
			"request Keycloak login page: %v",
			err,
		)
	}

	if keycloakLoginResponse.StatusCode != http.StatusOK {
		failResponse(
			t,
			keycloakLoginResponse,
			http.StatusOK,
			"Keycloak login page",
		)
	}

	loginFormAction, err := findLoginFormAction(
		keycloakLoginResponse.Body,
	)
	keycloakLoginResponse.Body.Close()

	if err != nil {
		t.Fatalf(
			"find Keycloak login form: %v",
			err,
		)
	}

	actionURL, err := keycloakLoginResponse.Request.URL.Parse(
		loginFormAction,
	)
	if err != nil {
		t.Fatalf(
			"resolve Keycloak login form action: %v",
			err,
		)
	}

	form := url.Values{
		"username": {username},
		"password": {password},
	}

	formRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		actionURL.String(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf(
			"create Keycloak login request: %v",
			err,
		)
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

	if keycloakCallbackResponse.StatusCode != http.StatusFound {
		failResponse(
			t,
			keycloakCallbackResponse,
			http.StatusFound,
			"Keycloak callback redirect",
		)
	}

	callbackURL := requireHeader(
		t,
		keycloakCallbackResponse,
		"Location",
	)
	keycloakCallbackResponse.Body.Close()

	assertCallbackURL(t, callbackURL)

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		callbackURL,
		nil,
	)
	callbackRequest.AddCookie(transactionCookie)

	callbackRecorder := httptest.NewRecorder()

	client.CallbackHandler().ServeHTTP(
		callbackRecorder,
		callbackRequest,
	)

	callbackResult := callbackRecorder.Result()
	callbackBody, err := io.ReadAll(callbackResult.Body)
	callbackResult.Body.Close()
	if err != nil {
		t.Fatalf(
			"read callback response body: %v",
			err,
		)
	}

	if callbackResult.StatusCode != http.StatusFound {
		t.Fatalf(
			"expected callback status %d, got %d: %s",
			http.StatusFound,
			callbackResult.StatusCode,
			string(callbackBody),
		)
	}

	callbackCookies := callbackResult.Cookies()

	sessionCookie := requireCookie(
		t,
		callbackCookies,
		testSessionCookieName,
	)

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

	return authenticatedTestSession{
		SessionCookie:    sessionCookie,
		Session:          session,
		TransactionID:    transactionID,
		CallbackResult:   callbackResult,
		CallbackCookies:  callbackCookies,
		CallbackLocation: callbackResult.Header.Get("Location"),
	}
}

func TestNew_WithValidKeycloakConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)
	defer cancel()

	store := auth.NewMemoryStore()

	client := newIntegrationAuthClient(
		t,
		ctx,
		store,
	)

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

	client := newIntegrationAuthClient(
		t,
		ctx,
		store,
	)

	result := executeHandler(
		t,
		client.LoginHandler(),
		http.MethodGet,
		testApplicationURL+"/login",
		nil,
	)
	defer result.Body.Close()

	if result.StatusCode != http.StatusFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusFound,
			result.StatusCode,
		)
	}

	location := requireHeader(t, result, "Location")

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

	assertQueryValue(t, query, "client_id", testClientID)
	assertQueryValue(t, query, "redirect_uri", testRedirectURL)
	assertQueryValue(t, query, "response_type", "code")
	assertQueryValue(t, query, "code_challenge_method", "S256")

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

	transactionCookie := requireCookie(
		t,
		result.Cookies(),
		testTransactionCookieName,
	)

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
		t.Error("stored state does not match redirect state")
	}

	if transaction.Nonce == "" {
		t.Error("expected stored nonce")
	}

	if transaction.Nonce != nonce {
		t.Error("stored nonce does not match redirect nonce")
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

func TestCallback_CreatesAuthenticatedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	store := auth.NewMemoryStore()

	client := newIntegrationAuthClient(
		t,
		ctx,
		store,
	)

	result := authenticateTestUser(
		t,
		ctx,
		client,
		store,
		testUsername,
		testPassword,
	)

	if result.CallbackLocation != "/dashboard" {
		t.Errorf(
			"expected success redirect %q, got %q",
			"/dashboard",
			result.CallbackLocation,
		)
	}

	assertAuthenticatedSession(t, result)

	_, err := store.GetTransaction(
		ctx,
		result.TransactionID,
	)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf(
			"expected authorization transaction to be deleted, got %v",
			err,
		)
	}

	clearedTransactionCookie := requireCookie(
		t,
		result.CallbackCookies,
		testTransactionCookieName,
	)

	if clearedTransactionCookie.MaxAge >= 0 {
		t.Errorf(
			"expected cleared transaction cookie MaxAge below zero, got %d",
			clearedTransactionCookie.MaxAge,
		)
	}
}

func TestRequireAuthentication_WithValidSession_AllowsRequest(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	store := auth.NewMemoryStore()

	client := newIntegrationAuthClient(
		t,
		ctx,
		store,
	)

	authenticatedSession := authenticateTestUser(
		t,
		ctx,
		client,
		store,
		testUsername,
		testPassword,
	)

	var handlerCalled bool

	protectedHandler := http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			handlerCalled = true

			claims, ok := auth.ClaimsFromContext(
				r.Context(),
			)
			if !ok {
				t.Error(
					"expected authenticated claims in request context",
				)

				http.Error(
					w,
					"claims unavailable",
					http.StatusInternalServerError,
				)
				return
			}

			if claims.Subject == "" {
				t.Error("expected nonempty subject claim")
			}

			if claims.Email != testEmail {
				t.Errorf(
					"expected email %q, got %q",
					testEmail,
					claims.Email,
				)
			}

			w.WriteHeader(http.StatusOK)

			_, _ = w.Write(
				[]byte("authenticated"),
			)
		},
	)

	handler := client.RequireAuthentication(
		protectedHandler,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		testApplicationURL+"/dashboard",
		nil,
	)

	request.AddCookie(
		authenticatedSession.SessionCookie,
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		request,
	)

	result := response.Result()
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf(
			"read protected response body: %v",
			err,
		)
	}

	if result.StatusCode != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusOK,
			result.StatusCode,
			string(body),
		)
	}

	if !handlerCalled {
		t.Fatal("expected protected handler to be called")
	}

	if string(body) != "authenticated" {
		t.Errorf(
			"expected response body %q, got %q",
			"authenticated",
			string(body),
		)
	}

	storedSession, err := store.GetSession(
		ctx,
		authenticatedSession.SessionCookie.Value,
	)
	if err != nil {
		t.Fatalf(
			"retrieve session after protected request: %v",
			err,
		)
	}

	if storedSession.Token == nil {
		t.Fatal(
			"expected stored OAuth token after protected request",
		)
	}

	if storedSession.Token.AccessToken == "" {
		t.Error(
			"expected stored access token after protected request",
		)
	}

	if storedSession.RawIDToken == "" {
		t.Error(
			"expected stored ID token after protected request",
		)
	}
}

func executeHandler(
	t *testing.T,
	handler http.Handler,
	method string,
	target string,
	cookies []*http.Cookie,
) *http.Response {
	t.Helper()

	request := httptest.NewRequest(
		method,
		target,
		nil,
	)

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response.Result()
}

func assertStatus(
	t *testing.T,
	response *http.Response,
	expected int,
) {
	t.Helper()

	if response.StatusCode == expected {
		response.Body.Close()
		return
	}

	body, _ := io.ReadAll(response.Body)
	response.Body.Close()

	t.Fatalf(
		"expected status %d, got %d: %s",
		expected,
		response.StatusCode,
		string(body),
	)
}

func requireHeader(
	t *testing.T,
	response *http.Response,
	name string,
) string {
	t.Helper()

	value := response.Header.Get(name)
	if value == "" {
		t.Fatalf(
			"expected nonempty %s header",
			name,
		)
	}

	return value
}

func requireCookie(
	t *testing.T,
	cookies []*http.Cookie,
	name string,
) *http.Cookie {
	t.Helper()

	cookie := findCookie(cookies, name)
	if cookie == nil {
		t.Fatalf(
			"expected cookie %q",
			name,
		)
	}

	return cookie
}

func failResponse(
	t *testing.T,
	response *http.Response,
	expected int,
	description string,
) {
	t.Helper()

	dump, err := httputil.DumpResponse(
		response,
		true,
	)
	if err != nil {
		t.Fatalf(
			"dump %s response: %v",
			description,
			err,
		)
	}

	response.Body.Close()

	t.Fatalf(
		"expected %s status %d, got %d:\n%s",
		description,
		expected,
		response.StatusCode,
		dump,
	)
}

func newKeycloakBrowser(
	t *testing.T,
) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf(
			"create HTTP cookie jar: %v",
			err,
		)
	}

	return &http.Client{
		Jar: jar,

		CheckRedirect: func(
			request *http.Request,
			via []*http.Request,
		) error {
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
}

func assertCallbackURL(
	t *testing.T,
	rawURL string,
) {
	t.Helper()

	callbackURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf(
			"parse callback URL %q: %v",
			rawURL,
			err,
		)
	}

	expectedApplicationURL, err := url.Parse(
		testApplicationURL,
	)
	if err != nil {
		t.Fatalf(
			"parse test application URL: %v",
			err,
		)
	}

	if callbackURL.Scheme != expectedApplicationURL.Scheme {
		t.Errorf(
			"expected callback scheme %q, got %q",
			expectedApplicationURL.Scheme,
			callbackURL.Scheme,
		)
	}

	if callbackURL.Host != expectedApplicationURL.Host {
		t.Errorf(
			"expected callback host %q, got %q",
			expectedApplicationURL.Host,
			callbackURL.Host,
		)
	}

	if callbackURL.Path != "/callback" {
		t.Errorf(
			"expected callback path %q, got %q",
			"/callback",
			callbackURL.Path,
		)
	}

	query := callbackURL.Query()

	if authorizationError := query.Get("error"); authorizationError != "" {
		t.Fatalf(
			"Keycloak returned authorization error %q: %s",
			authorizationError,
			query.Get("error_description"),
		)
	}

	if query.Get("code") == "" {
		t.Error("expected callback authorization code")
	}

	if query.Get("state") == "" {
		t.Error("expected callback state")
	}
}

func assertAuthenticatedSession(
	t *testing.T,
	result authenticatedTestSession,
) {
	t.Helper()

	cookie := result.SessionCookie
	session := result.Session

	if cookie.Value == "" {
		t.Error("expected nonempty session cookie value")
	}

	if !cookie.HttpOnly {
		t.Error("expected session cookie to be HttpOnly")
	}

	if cookie.Secure {
		t.Error(
			"expected session cookie Secure=false in HTTP test",
		)
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf(
			"expected session cookie SameSite %v, got %v",
			http.SameSiteLaxMode,
			cookie.SameSite,
		)
	}

	if cookie.Path != "/" {
		t.Errorf(
			"expected session cookie path %q, got %q",
			"/",
			cookie.Path,
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
	} else if !session.Token.Expiry.After(time.Now()) {
		t.Errorf(
			"expected access token expiration in the future, got %s",
			session.Token.Expiry,
		)
	}

	if session.RawIDToken == "" {
		t.Error("expected raw ID token")
	}

	if session.ExpiresAt.IsZero() {
		t.Error("expected application session expiration")
	} else if !session.ExpiresAt.After(time.Now()) {
		t.Errorf(
			"expected application session expiration in the future, got %s",
			session.ExpiresAt,
		)
	}

	assertOpaqueSessionCookie(t, cookie, session)
}

func assertOpaqueSessionCookie(
	t *testing.T,
	cookie *http.Cookie,
	session auth.Session,
) {
	t.Helper()

	if strings.Contains(
		cookie.Value,
		session.Token.AccessToken,
	) {
		t.Error("session cookie contains access token")
	}

	if strings.Contains(
		cookie.Value,
		session.Token.RefreshToken,
	) {
		t.Error("session cookie contains refresh token")
	}

	if strings.Contains(
		cookie.Value,
		session.RawIDToken,
	) {
		t.Error("session cookie contains ID token")
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
