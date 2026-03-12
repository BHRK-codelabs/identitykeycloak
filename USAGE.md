# Usage

## Create a connector

```go
connector, err := keycloak.New(configkit.IdentityConfig{
    IssuerURL:    "https://auth.example.com/realms/acme",
    JWKSEndpoint: "https://auth.example.com/realms/acme/protocol/openid-connect/certs",
    ClientID:     "payments-api",
})
if err != nil {
    return err
}
```

## Authenticate a token

```go
principal, err := connector.Authenticate(ctx, bearerToken)
```

The resulting principal is mapped into `identitykit.Principal`.

## Notes

- `RS256` is the supported algorithm in the current implementation
- issuer and audience/client validation are enforced
- tenant and actor information can be projected from claims such as `tenant_id` and `actor_id`
