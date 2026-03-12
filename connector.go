package keycloak

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BHRK-codelabs/identitykit"
	"github.com/BHRK-codelabs/corekit/configkit"
)

type Connector struct {
	issuerURL    string
	jwksEndpoint string
	audience     string
	clientID     string
	httpClient   *http.Client

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func New(cfg configkit.IdentityConfig) (*Connector, error) {
	if strings.TrimSpace(cfg.IssuerURL) == "" {
		return nil, fmt.Errorf("identity issuer url is required for keycloak")
	}
	if strings.TrimSpace(cfg.JWKSEndpoint) == "" {
		return nil, fmt.Errorf("identity jwks endpoint is required for keycloak")
	}

	return &Connector{
		issuerURL:    cfg.IssuerURL,
		jwksEndpoint: cfg.JWKSEndpoint,
		audience:     firstNonEmpty(cfg.Audience, cfg.ClientID),
		clientID:     cfg.ClientID,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		keys: make(map[string]*rsa.PublicKey),
	}, nil
}

func (c *Connector) Authenticate(ctx context.Context, token string) (identitykit.Principal, error) {
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if token == "" {
		return identitykit.Principal{}, identitykit.ErrUnauthenticated
	}

	header, claims, signingInput, signature, err := parseJWT(token)
	if err != nil {
		return identitykit.Principal{}, err
	}
	if header.Alg != "RS256" {
		return identitykit.Principal{}, identitykit.ErrUnauthorized
	}

	key, err := c.lookupKey(ctx, header.Kid)
	if err != nil {
		return identitykit.Principal{}, err
	}
	if err := verifyRS256(key, signingInput, signature); err != nil {
		return identitykit.Principal{}, identitykit.ErrUnauthorized
	}
	if err := validateClaims(claims, c.issuerURL, c.audience, c.clientID); err != nil {
		return identitykit.Principal{}, err
	}

	return identitykit.Principal{
		Subject:   claims.Subject,
		TenantID:  firstNonEmpty(claims.TenantID, claims.Claims["tenant_id"]),
		ActorID:   firstNonEmpty(claims.ActorID, claims.Subject),
		Provider:  "keycloak",
		Scopes:    parseScopes(claims.Scope),
		Roles:     claims.RealmAccess.Roles,
		Claims:    claims.Claims,
		TokenType: firstNonEmpty(claims.TokenType, "Bearer"),
	}, nil
}

type tokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type tokenClaims struct {
	Subject     string            `json:"sub"`
	Issuer      string            `json:"iss"`
	Audience    audienceClaim     `json:"aud"`
	ExpiresAt   int64             `json:"exp"`
	NotBefore   int64             `json:"nbf"`
	IssuedAt    int64             `json:"iat"`
	Scope       string            `json:"scope"`
	TokenType   string            `json:"typ"`
	Preferred   string            `json:"preferred_username"`
	TenantID    string            `json:"tenant_id"`
	ActorID     string            `json:"actor_id"`
	RealmAccess realmAccessClaims `json:"realm_access"`
	Claims      map[string]string `json:"-"`
}

type realmAccessClaims struct {
	Roles []string `json:"roles"`
}

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func parseJWT(token string) (tokenHeader, tokenClaims, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenHeader{}, tokenClaims{}, "", nil, identitykit.ErrUnauthenticated
	}

	headerBytes, err := decodeRaw(parts[0])
	if err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}
	payloadBytes, err := decodeRaw(parts[1])
	if err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}
	signature, err := decodeRaw(parts[2])
	if err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}

	var header tokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}

	payloadCopy, _ := json.Marshal(rawClaims)
	var claims tokenClaims
	if err := json.Unmarshal(payloadCopy, &claims); err != nil {
		return tokenHeader{}, tokenClaims{}, "", nil, err
	}
	claims.Claims = make(map[string]string)
	for key, value := range rawClaims {
		if str, ok := value.(string); ok {
			claims.Claims[key] = str
		}
	}

	return header, claims, parts[0] + "." + parts[1], signature, nil
}

func validateClaims(claims tokenClaims, issuer, audience, clientID string) error {
	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now >= claims.ExpiresAt {
		return identitykit.ErrUnauthorized
	}
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return identitykit.ErrUnauthorized
	}
	if issuer != "" && claims.Issuer != issuer {
		return identitykit.ErrUnauthorized
	}
	if audience != "" && !claims.Audience.contains(audience) {
		return identitykit.ErrUnauthorized
	}
	if clientID != "" && audience == "" && !claims.Audience.contains(clientID) {
		return identitykit.ErrUnauthorized
	}
	if claims.Subject == "" {
		return identitykit.ErrUnauthorized
	}
	return nil
}

func (a audienceClaim) contains(target string) bool {
	for _, item := range a {
		if item == target {
			return true
		}
	}
	return false
}

func (c *Connector) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}
	if err := c.refreshKeys(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, identitykit.ErrUnauthorized
	}
	return key, nil
}

func (c *Connector) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksEndpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" {
			continue
		}
		pub, err := jwkToPublicKey(jwk.N, jwk.E)
		if err != nil {
			return err
		}
		keys[jwk.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

func jwkToPublicKey(n, e string) (*rsa.PublicKey, error) {
	modBytes, err := decodeRaw(n)
	if err != nil {
		return nil, err
	}
	expBytes, err := decodeRaw(e)
	if err != nil {
		return nil, err
	}
	if len(expBytes) == 0 {
		return nil, errors.New("empty jwk exponent")
	}

	modulus := new(big.Int).SetBytes(modBytes)
	exponent := 0
	for _, b := range expBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, errors.New("invalid jwk exponent")
	}
	return &rsa.PublicKey{N: modulus, E: exponent}, nil
}

func verifyRS256(key *rsa.PublicKey, signingInput string, signature []byte) error {
	sum := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature)
}

func decodeRaw(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func parseScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

