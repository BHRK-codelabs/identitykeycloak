# identitykeycloak docs

This package adapts Keycloak to the neutral `identitykit` capability.

It is responsible for:
- parsing bearer tokens
- validating `RS256` signatures
- loading JWKS keys
- validating issuer and audience/client identity
- mapping token claims into a neutral principal

It is intended to be wired by application bootstrap or artifact composition code, not by the capability package itself.
