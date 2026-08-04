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
	defer func() {
		if r := recover(); r != nil {
			shutDown()
			fmt.Println("Panic")
		}
	}()
	integrationEnvironment.IssuerURL = "http://127.0.0.1:8080/realms/integration-test"
	setup()
	code := m.Run()
	shutDown()
	os.Exit(code)
}

func setup() {
	var err error
	ctx := context.Background()
	keycloakContainer, err = RunContainer(ctx)
	if err != nil {
		panic(err)
	}
}

func shutDown() {
	ctx := context.Background()
	err := keycloakContainer.Terminate(ctx)
	if err != nil {
		panic(err)
	}
}

func RunContainer(ctx context.Context) (*keycloak.KeycloakContainer, error) {
	return keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.7.0",
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8080/tcp").WithStartupTimeout(60*time.Second)),
		keycloak.WithContextPath(""),
		keycloak.WithRealmImportFile("./test_data/integration_test_realm.json"),
		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
}
