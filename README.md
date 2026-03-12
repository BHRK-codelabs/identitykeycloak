# identitykeycloak

`identitykeycloak` is the Keycloak adapter for `capabilities/identitykit`.

It provides:
- JWT bearer token authentication
- JWKS-based RSA key lookup
- issuer and audience validation
- principal mapping into `identitykit.Principal`

## Package structure

- `connector.go`: Keycloak connector implementation

## Local docs

- [Overview](OVERVIEW.md)
- [Usage](USAGE.md)

## Design notes

- this package is a connector, not part of the neutral capability
- it implements `identitykit.Authenticator`
- provider-specific token and JWKS behavior stays here, not in `identitykit`
