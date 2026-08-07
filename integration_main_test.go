package auth_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	keycloak "github.com/stillya/testcontainers-keycloak"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testRealm        = "integration-test"
	testClientID     = "go-auth-test"
	testClientSecret = "test-client-secret"
	testRedirectURL  = "http://127.0.0.1:8081/callback"
)

var integrationEnvironment struct {
	IssuerURL string
}

var keycloakContainer *keycloak.KeycloakContainer

func TestMain(m *testing.M) {
	exitCode := runIntegrationTests(m)
	os.Exit(exitCode)
}

func runIntegrationTests(m *testing.M) int {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Minute,
	)
	defer cancel()

	container, err := runKeycloakContainer(ctx)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"start Keycloak integration container: %v\n",
			err,
		)
		return 1
	}

	keycloakContainer = container
	integrationEnvironment.IssuerURL =
		"http://127.0.0.1:8080/realms/" + testRealm

	exitCode := m.Run()

	cleanupContext, cleanupCancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cleanupCancel()

	if err := keycloakContainer.Terminate(cleanupContext); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"terminate Keycloak integration container: %v\n",
			err,
		)

		if exitCode == 0 {
			exitCode = 1
		}
	}

	return exitCode
}

func runKeycloakContainer(
	ctx context.Context,
) (*keycloak.KeycloakContainer, error) {
	return keycloak.Run(
		ctx,
		"quay.io/keycloak/keycloak:26.7.0",

		testcontainers.WithWaitStrategy(
			wait.ForHTTP(
				"/realms/"+
					testRealm+
					"/.well-known/openid-configuration",
			).
				WithPort("8080/tcp").
				WithStatusCodeMatcher(
					func(status int) bool {
						return status == 200
					},
				).
				WithStartupTimeout(90*time.Second),
		),

		keycloak.WithContextPath(""),

		keycloak.WithRealmImportFile(
			"./test_data/integration_test_realm.json",
		),

		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
}
