package keycloak

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BHRK-codelabs/corekit/configkit"
)

func TestConnectorAuthenticatesValidToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{
					"kid": "kid-1",
					"kty": "RSA",
					"n":   encodeRaw(privateKey.PublicKey.N.Bytes()),
					"e":   encodeRaw(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		})
	}))
	defer jwks.Close()

	connector, err := New(configkit.IdentityConfig{
		Provider:     "keycloak",
		IssuerURL:    "https://id.example.com/realms/core",
		JWKSEndpoint: jwks.URL,
		ClientID:     "core-api",
		Audience:     "core-api",
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}

	token := signToken(t, privateKey, map[string]any{
		"sub":       "user-1",
		"iss":       "https://id.example.com/realms/core",
		"aud":       "core-api",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"scope":     "openid profile",
		"tenant_id": "tenant-1",
		"actor_id":  "actor-1",
		"realm_access": map[string]any{
			"roles": []string{"admin", "user"},
		},
	})

	principal, err := connector.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.Subject != "user-1" {
		t.Fatalf("unexpected subject: %s", principal.Subject)
	}
	if principal.TenantID != "tenant-1" {
		t.Fatalf("unexpected tenant id: %s", principal.TenantID)
	}
	if len(principal.Roles) != 2 {
		t.Fatalf("unexpected roles: %#v", principal.Roles)
	}
}

func TestConnectorRejectsWrongAudience(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{
					"kid": "kid-1",
					"kty": "RSA",
					"n":   encodeRaw(privateKey.PublicKey.N.Bytes()),
					"e":   encodeRaw(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		})
	}))
	defer jwks.Close()

	connector, err := New(configkit.IdentityConfig{
		Provider:     "keycloak",
		IssuerURL:    "https://id.example.com/realms/core",
		JWKSEndpoint: jwks.URL,
		ClientID:     "core-api",
		Audience:     "core-api",
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}

	token := signToken(t, privateKey, map[string]any{
		"sub": "user-1",
		"iss": "https://id.example.com/realms/core",
		"aud": "other-api",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	if _, err := connector.Authenticate(context.Background(), token); err == nil {
		t.Fatal("expected authentication error")
	}
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"kid": "kid-1",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := encodeRaw(headerJSON) + "." + encodeRaw(payloadJSON)
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + encodeRaw(signature)
}

func encodeRaw(value []byte) string {
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(value), "=")
}

