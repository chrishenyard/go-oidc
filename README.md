# Go OIDC Authentication Package

This project demonstrates how to add OpenID Connect authentication and role-based authorization to a Go web application.

The OIDC implementation is separated into a reusable `auth` package. The application in `main.go` is responsible only for configuration, route registration, logging, and application-specific handlers.

The authentication package handles:

* OpenID Connect provider discovery
* OAuth 2.0 Authorization Code flow
* PKCE protection
* OIDC state and nonce validation
* Authorization-code exchange
* ID token verification
* Server-side sessions
* Access-token expiration
* Refresh-token usage
* Refresh-token rotation
* Role-based access control
* Login, callback, and logout handlers
* Typed library errors
* Configurable HTTP error handling
* Optional debug logging with `log/slog`

The example is configured to use Keycloak, but the package can work with other standards-compliant OpenID Connect providers.

## Project Structure

```text
go-oidc/
│── errors.go
│── memory_store.go
│── middleware.go
│── oidc.go
├── go.mod
├── go.sum

```

## Authentication Flow

The application uses the OAuth 2.0 Authorization Code flow with PKCE.

```text
Browser
   |
   | GET /login
   v
Go application
   |
   | Redirect to Keycloak
   | state
   | nonce
   | code_challenge
   v
Keycloak
   |
   | User signs in
   | Redirects to /callback
   | authorization code
   v
Go application
   |
   | Validates state
   | Exchanges code with code_verifier
   | Verifies ID token
   | Validates nonce
   | Creates server-side session
   v
Browser
   |
   | Receives opaque session cookie
   v
Protected routes
```

The browser does not receive the refresh token. The access token, refresh token, and ID token are stored in the server-side session store.

## Token Refresh

Before a protected route is executed, the authentication middleware retrieves the user's OAuth token from the server-side session.

The package creates an OAuth token source:

```go
tokenSource := oauth2Config.TokenSource(ctx, existingToken)
```

Calling `Token()` on the token source behaves as follows:

* If the access token is still valid, the existing token is returned.
* If the access token has expired, the refresh token is sent to the provider.
* If the provider rotates the refresh token, the new refresh token is saved.
* If the refresh fails, the session is deleted and the user must authenticate again.

```go
currentToken, err := tokenSource.Token()
```

The application session expiration and access-token expiration are intentionally separate.

An access token can expire several times during one application session. The refresh token allows the server to obtain new access tokens without requiring the user to sign in again.

## Packages

### `auth/oidc.go`

Contains the main OIDC client and authentication flow.

Responsibilities include:

* Validating authentication configuration
* Performing provider discovery
* Building the OAuth configuration
* Creating the ID token verifier
* Starting the login flow
* Handling the callback
* Exchanging authorization codes
* Validating state and nonce values
* Creating authenticated sessions
* Deleting sessions during logout
* Managing authentication cookies

The package exposes handlers that can be registered directly with an HTTP router:

```go
mux.Handle("/login", authClient.LoginHandler())
mux.Handle("/callback", authClient.CallbackHandler())
mux.Handle("/logout", authClient.LogoutHandler())
```

### `auth/middleware.go`

Contains authentication and authorization middleware.

The package provides middleware for authenticated routes:

```go
authClient.RequireAuthentication(handler)
```

It also provides role-based middleware:

```go
authClient.RequireRole("admin", handler)
```

The middleware:

1. Reads the session cookie.
2. Retrieves the server-side session.
3. checks the OAuth token.
4. Refreshes the token when necessary.
5. Saves rotated tokens.
6. Verifies the current ID token.
7. Decodes the configured claims.
8. Checks the required role.
9. Adds the verified claims to the request context.

Application handlers retrieve the claims with:

```go
claims, ok := auth.ClaimsFromContext(r.Context())
```

### `auth/memory_store.go`

Defines the server-side session storage interface.

```go
type Store interface {
    SaveTransaction(
        ctx context.Context,
        id string,
        transaction AuthorizationTransaction,
    ) error

    GetTransaction(
        ctx context.Context,
        id string,
    ) (AuthorizationTransaction, error)

    DeleteTransaction(
        ctx context.Context,
        id string,
    ) error

    SaveSession(
        ctx context.Context,
        id string,
        session Session,
    ) error

    GetSession(
        ctx context.Context,
        id string,
    ) (Session, error)

    DeleteSession(
        ctx context.Context,
        id string,
    ) error
}
```

The included `MemoryStore` is suitable for local development and demonstrations.

```go
store := auth.NewMemoryStore()
```

Because the memory store is local to one process:

* Sessions are lost when the application restarts.
* Sessions are not shared between application instances.
* It should not be used as the final session store for a distributed deployment.

A production implementation can replace it with Redis, SQL Server, PostgreSQL, or another shared storage system.

### `auth/errors.go`

Defines package-level sentinel errors and the exported `auth.Error` type.

Examples include:

```go
auth.ErrAuthentication
auth.ErrAuthorization
auth.ErrInvalidState
auth.ErrInvalidNonce
auth.ErrSessionNotFound
auth.ErrTokenRefresh
auth.ErrInsufficientRole
```

Callers can inspect errors with `errors.Is`:

```go
if errors.Is(err, auth.ErrTokenRefresh) {
    // Handle refresh failure.
}
```

Additional error details can be inspected with `errors.As`:

```go
var authError *auth.Error

if errors.As(err, &authError) {
    log.Printf(
        "operation=%s code=%s error=%v",
        authError.Operation,
        authError.Code,
        authError.Err,
    )
}
```

The authentication package does not terminate the process.

The application decides where logs are written and can enable package debug logs by providing a `*slog.Logger` in `auth.Config`.

## Debug Logging With slog

The auth package emits debug-level lifecycle events (login, callback, token refresh, middleware authentication/authorization, and logout) when a logger is configured.

If `Config.Logger` is nil, logging is disabled.

```go
package main

import (
    "context"
    "log/slog"
    "net/http"
    "os"

    auth "github.com/chrishenyard/go-oidc"
)

func main() {
    logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    }))

    client, err := auth.New(context.Background(), auth.Config{
        IssuerURL:    "http://localhost:8080/realms/my-realm",
        ClientID:     "my-client",
        ClientSecret: "my-secret",
        RedirectURL:  "http://localhost:8081/callback",
        Store:        auth.NewMemoryStore(),
        Logger:       logger,
    })
    if err != nil {
        panic(err)
    }

    http.Handle("/login", client.LoginHandler())
    http.Handle("/callback", client.CallbackHandler())
    http.Handle("/logout", client.LogoutHandler())

    http.Handle(
        "/api/admin",
        client.RequireRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
            _, _ = w.Write([]byte("ok"))
        })),
    )

    _ = http.ListenAndServe(":8081", nil)
}
```

Example debug log lines:

```text
time=2026-08-08T12:00:00.123Z level=DEBUG msg="auth middleware started" method=GET path=/api/admin
time=2026-08-08T12:00:00.124Z level=DEBUG msg="authenticating request" operation=auth.Client.authenticateRequest method=GET path=/api/admin
time=2026-08-08T12:00:00.130Z level=DEBUG msg="request authenticated" operation=auth.Client.authenticateRequest subject=7f3f1a4b role_count=2 scope_count=3
```

## Requirements

* Go 1.21 or later
* A standards-compliant OpenID Connect provider
* A configured OAuth or OIDC client
* Keycloak, if using the included example configuration

Install the dependencies:

```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
```

Then tidy the module:

```bash
go mod tidy
```

## Keycloak Configuration

The example expects Keycloak to be available at:

```text
http://localhost:8080
```

The example realm is:

```text
Golang_Private
```

The issuer URL is therefore:

```text
http://localhost:8080/realms/Golang_Private
```

Create or configure a Keycloak client with values similar to the following:

```text
Client ID: go-web-api-client-private
Client authentication: enabled
Standard flow: enabled
Valid redirect URI: http://localhost:8081/callback
Web origin: http://localhost:8081
```

The exact Keycloak settings depend on the Keycloak version and deployment.

The redirect URI must exactly match the value configured in the Go application:

```go
RedirectURL: "http://localhost:8081/callback",
```

## Client Secret

Do not hardcode the OIDC client secret in source code.

Set it through an environment variable:

### Linux or macOS

```bash
export OIDC_CLIENT_SECRET="your-client-secret"
```

### PowerShell

```powershell
$env:OIDC_CLIENT_SECRET = "your-client-secret"
```

The application reads it with:

```go
ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
```

For Kubernetes, store the client secret in a Kubernetes `Secret` or retrieve it through a secret-management system such as HashiCorp Vault.

## Roles Claim

The example claims structure expects roles to appear as a top-level `roles` claim:

```go
type Claims struct {
    Subject string   `json:"sub"`
    Email   string   `json:"email"`
    Roles   []string `json:"roles"`
}
```

An example token payload would contain:

```json
{
  "sub": "e7cc9cd6-57d6-4d77-8a32-bcc9ce67d307",
  "email": "user@example.com",
  "roles": [
    "user",
    "admin"
  ]
}
```

Keycloak does not necessarily place roles in this exact location by default.

You may need to create a Keycloak protocol mapper that adds realm or client roles to a top-level `roles` claim.

Alternatively, change the Go claims structure to match Keycloak's default token structure.

For example, realm roles commonly appear under `realm_access`:

```go
type Claims struct {
    Subject string `json:"sub"`
    Email   string `json:"email"`

    RealmAccess struct {
        Roles []string `json:"roles"`
    } `json:"realm_access"`
}
```

The role check would then use:

```go
claims.RealmAccess.Roles
```

## Configuring the Authentication Client

Create the authentication client during application startup:

```go
store := auth.NewMemoryStore()

authClient, err := auth.New(
    context.Background(),
    auth.Config{
        IssuerURL: "http://localhost:8080/realms/Golang_Private",

        ClientID:     "go-web-api-client-private",
        ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),

        RedirectURL: "http://localhost:8081/callback",

        Scopes: []string{
            "openid",
            "profile",
            "email",
            "roles",
        },

        Store: store,

        CookieSecure: false,

        TransactionLifetime: 5 * time.Minute,
        SessionLifetime:     8 * time.Hour,

        LoginSuccessURL: "/dashboard",

        ErrorHandler: authenticationErrorHandler,
    },
)
if err != nil {
    return fmt.Errorf("initialize authentication: %w", err)
}
```

### Configuration Options

| Option                  | Description                                      |
| ----------------------- | ------------------------------------------------ |
| `IssuerURL`             | OIDC issuer URL used for provider discovery      |
| `ClientID`              | OAuth client identifier                          |
| `ClientSecret`          | OAuth client secret                              |
| `RedirectURL`           | Application callback URL                         |
| `Scopes`                | Scopes requested from the provider               |
| `Store`                 | Server-side transaction and session store        |
| `TransactionCookieName` | Optional login-transaction cookie name           |
| `SessionCookieName`     | Optional application session cookie name         |
| `TransactionLifetime`   | Maximum duration of a login transaction          |
| `SessionLifetime`       | Maximum duration of an application session       |
| `CookieSecure`          | Restricts cookies to HTTPS                       |
| `CookieSameSite`        | Controls browser cross-site cookie behavior      |
| `LoginSuccessURL`       | Redirect destination after successful login      |
| `ErrorHandler`          | Application-defined authentication error handler |

## Registering Routes

Register the login, callback, and logout handlers:

```go
mux.Handle("/login", authClient.LoginHandler())
mux.Handle("/callback", authClient.CallbackHandler())
mux.Handle("/logout", authClient.LogoutHandler())
```

Protect an endpoint that requires authentication:

```go
mux.Handle(
    "/profile",
    authClient.RequireAuthentication(
        http.HandlerFunc(handleProfile),
    ),
)
```

Protect an endpoint with a role:

```go
mux.Handle(
    "/dashboard",
    authClient.RequireRole(
        "user",
        http.HandlerFunc(handleDashboard),
    ),
)
```

Protect an administrator endpoint:

```go
mux.Handle(
    "/admin",
    authClient.RequireRole(
        "admin",
        http.HandlerFunc(handleAdmin),
    ),
)
```

## Reading Claims

Verified claims are added to the request context by the authentication middleware.

```go
func handleDashboard(
    w http.ResponseWriter,
    r *http.Request,
) {
    claims, ok := auth.ClaimsFromContext(r.Context())
    if !ok {
        http.Error(
            w,
            "authenticated claims are unavailable",
            http.StatusInternalServerError,
        )
        return
    }

    fmt.Fprintf(
        w,
        "Welcome to the dashboard, %s!",
        claims.Email,
    )
}
```

Do not decode an unverified token again inside the application handler. Use the claims placed in the context by the middleware.

## Running the Application

Start Keycloak and ensure the configured realm and client exist.

Set the client secret:

```bash
export OIDC_CLIENT_SECRET="your-client-secret"
```

Run the application:

```bash
go run .
```

The server listens at:

```text
http://localhost:8081
```

Start the login flow by visiting:

```text
http://localhost:8081/login
```

After successful authentication, the application redirects to:

```text
http://localhost:8081/dashboard
```

Other example routes include:

```text
http://localhost:8081/admin
http://localhost:8081/logout
```

## Offline Access

The standard scopes are:

```go
Scopes: []string{
    "openid",
    "profile",
    "email",
    "roles",
},
```

To request a Keycloak offline token, add:

```go
"offline_access",
```

For example:

```go
Scopes: []string{
    "openid",
    "profile",
    "email",
    "roles",
    "offline_access",
},
```

An offline token can remain usable independently of the user's normal Keycloak login session, subject to the realm's offline-session policies.

Do not request `offline_access` unless the application needs that behavior.

A regular server-side web session normally requires only a standard refresh token.

## Cookie Security

The development configuration uses:

```go
CookieSecure: false,
```

This is necessary when testing over plain HTTP.

Production deployments using HTTPS should use:

```go
CookieSecure: true,
```

The package creates cookies with:

```text
HttpOnly: true
SameSite: Lax
Path: /
```

`HttpOnly` prevents normal browser JavaScript from reading the cookie.

`SameSite=Lax` allows the browser to include the transaction cookie on the top-level redirect from the identity provider back to the callback endpoint.

The session cookie contains only an opaque random session identifier. It does not contain the access token, refresh token, or ID token.

## Library Error Handling

The package returns errors rather than:

* Calling `log.Fatal`
* Calling `panic`
* Printing logs
* Exposing raw identity-provider errors to users

The application can provide an error handler:

```go
func authenticationErrorHandler(
    w http.ResponseWriter,
    r *http.Request,
    err error,
) {
    log.Printf(
        "authentication error: method=%s path=%s error=%v",
        r.Method,
        r.URL.Path,
        err,
    )

    auth.DefaultErrorHandler(w, r, err)
}
```

The default error handler returns safe, general HTTP messages.

Detailed errors remain available to server-side logs through the wrapped error.

## Production Considerations

### Use HTTPS

Production applications should use HTTPS and enable secure cookies:

```go
CookieSecure: true,
```

### Use a Shared Session Store

Replace `MemoryStore` when running multiple backend instances.

Suitable choices include:

* Redis
* SQL Server
* PostgreSQL
* MySQL
* A distributed cache
* An encrypted shared session service

All application instances must be able to read and update the same session.

### Serialize Refresh Operations

Two simultaneous requests can observe the same expired access token and both attempt to use the same refresh token.

This can cause problems when refresh-token rotation is enabled. One request may rotate the refresh token while the second request is still using the old value.

A production implementation should serialize refresh operations for each session.

Possible approaches include:

* A per-session mutex
* `singleflight`
* An atomic store update
* A Redis distributed lock
* A database transaction with row locking

This is especially important when the application runs across multiple backend instances.

### Encrypt Stored Tokens

The session store contains security-sensitive values:

* Access tokens
* Refresh tokens
* ID tokens

Protect the session store with:

* Encryption at rest
* Strict network access
* Least-privilege service credentials
* Expiration and cleanup policies
* Audit logging
* Secret rotation procedures

### Do Not Log Tokens

Never log:

* Access tokens
* Refresh tokens
* ID tokens
* Authorization codes
* Client secrets
* Session IDs

Logging the wrapped error is useful, but review provider errors before enabling verbose logs in production.

### Use Typed Context Keys

The package uses a private context-key type rather than a string:

```go
type claimsContextKey struct{}
```

This avoids collisions with values added by other middleware.

### Configure HTTP Timeouts

The example server defines timeouts:

```go
server := &http.Server{
    Addr:              ":8081",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      15 * time.Second,
    IdleTimeout:       60 * time.Second,
}
```

Production applications should also implement graceful shutdown.

## API Usage

### Create a client

```go
client, err := auth.New(ctx, auth.Config{
    IssuerURL:   issuerURL,
    ClientID:    clientID,
    ClientSecret: clientSecret,
    RedirectURL: redirectURL,
    Store:       auth.NewMemoryStore(),
})
```

### Start login

```go
mux.Handle("/login", client.LoginHandler())
```

### Handle the callback

```go
mux.Handle("/callback", client.CallbackHandler())
```

### Log out

```go
mux.Handle("/logout", client.LogoutHandler())
```

### Require authentication

```go
mux.Handle(
    "/account",
    client.RequireAuthentication(accountHandler),
)
```

### Require a role

```go
mux.Handle(
    "/admin",
    client.RequireRole("admin", adminHandler),
)
```

### Read verified claims

```go
claims, ok := auth.ClaimsFromContext(r.Context())
```

### Inspect a package error

```go
if errors.Is(err, auth.ErrTokenRefresh) {
    // The session could not be refreshed.
}
```

## Security Properties

The implementation provides the following protections:

### State Validation

The application generates a random OAuth state value before redirecting to the provider.

The callback must contain the same state value. This helps prevent login CSRF and unsolicited callback requests.

### Nonce Validation

The application sends a random nonce in the authorization request.

After verifying the ID token, the application checks that the token contains the expected nonce. This helps prevent ID token replay during the initial login flow.

### PKCE

The application generates a PKCE verifier and sends its SHA-256 challenge during authorization.

The original verifier is sent during the authorization-code exchange.

A stolen authorization code cannot be exchanged without the verifier.

### ID Token Verification

The OIDC verifier validates the token using provider metadata and signing keys.

Verification includes important checks such as:

* Signature
* Issuer
* Audience
* Expiration

### Server-Side Tokens

OAuth tokens are stored on the server. The browser receives only a random session identifier.

### Constant-Time Comparisons

Security-sensitive state and nonce values are compared with a constant-time comparison function.

## Limitations

The included example intentionally remains small and understandable.

It does not currently include:

* Persistent session storage
* Distributed refresh locking
* CSRF protection for application form submissions
* Provider-side logout
* Back-channel logout
* Front-channel logout
* Token revocation
* Session renewal
* Graceful server shutdown
* Metrics
* Structured logging
* OpenTelemetry tracing
* Automated key rotation tests
* Multiple identity providers
* Custom claim mapping
* Permission-based authorization

These features can be added without placing application-specific code inside the core OIDC package.

## License

```text
MIT License
```
