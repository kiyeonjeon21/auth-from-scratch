---
name: keycloak-lab
description: Operate the local Keycloak IdP for this repo - start, reset, add a client or user, change feature flags, and debug realm import or redirect_uri failures. Use whenever a chapter needs new IdP configuration or the login flow fails before reaching application code.
---

# Keycloak lab

The IdP is a single pinned container defined in `docker-compose.yml`, configured entirely by
`docker/keycloak/realm-demo.json`.

## Non-negotiables

- **The realm JSON is the only source of truth.** Never make a change by clicking in the admin
  console and leave it there. It dies at the next reset.
- **After editing the realm JSON, run `make kc-reset`, not `make kc-up`.** `kc-up` reuses the
  existing volume, so the edit silently does nothing and you debug the wrong layer for an hour.
- **Never add comment keys** (`_comment`, `//`, ...) to the realm JSON. The importer rejects
  unknown fields and Keycloak refuses to start. Put the explanation in
  `docker/keycloak/README.md`.
- **Never bump the image to `latest`.** Feature flag names move between releases.

## Commands

```bash
make kc-up        # start, block until the discovery endpoint answers
make kc-reset     # docker compose down -v, then kc-up   <- the one you usually want
make kc-logs      # tail
make kc-export    # dump the running realm to stdout, to fold console experiments back into the file
make discovery    # pretty-print the discovery document
```

## Adding a client

Append to `clients` in `realm-demo.json`, then `make kc-reset`.

```json
{
  "clientId": "demo-spa",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "redirectUris": ["http://localhost:5556/callback"],
  "webOrigins": ["http://localhost:5556"],
  "attributes": { "pkce.code.challenge.method": "S256" }
}
```

`publicClient: true` means no secret, so PKCE is mandatory rather than optional.
Confidential clients set `"publicClient": false` and `"secret": "..."`.

Keep every redirect URI on port `5556` unless the chapter needs a second app;
then give the second app its own port and its own client.

## Feature flags

Set in the `--features=` line of `docker-compose.yml`. Currently on:

| flag | chapter |
|---|---|
| `token-exchange-standard:v2` | 06 token exchange |
| `dpop:v1` | 08 sender-constrained |

Verify a flag exists for the pinned version before adding it:

```bash
docker run --rm quay.io/keycloak/keycloak:26.2 build --help-all | grep -A2 'token-exchange'
```

On 26.2 the standard RFC 8693 flag is `token-exchange-standard` (v2).
Plain `token-exchange` is the legacy v1 mechanism and is not the same thing.

## Failure triage

Work outside in. Most "OIDC is broken" reports are one of these.

| Symptom | Cause | Fix |
|---|---|---|
| `make kc-up` times out | import failed, server never started | `make kc-logs`, look for `Unrecognized field` or `Failed to run import` |
| `Invalid parameter: redirect_uri` on the IdP login page | app port != `redirectUris` in realm JSON | fix the JSON, `make kc-reset` |
| Realm edits have no effect | reused the old volume | `make kc-reset` |
| `invalid_client` at the token endpoint | client id/secret mismatch, or client is public but the app sends a secret | compare against the realm JSON |
| `unauthorized_client` for a grant | grant not enabled on the client, or feature flag missing | check `standardFlowEnabled` / `serviceAccountsEnabled` / `--features` |
| Discovery works, login page 404s | wrong realm in the issuer URL, often `master` | issuer must be `http://localhost:8080/realms/demo` |

Reproduce end to end in a browser before changing code.
If the failure happens before the callback reaches the app, it is IdP configuration, not application logic.
