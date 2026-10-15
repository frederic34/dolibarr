# OAuth 2.1 authorization server

The `oauthserver` module turns Dolibarr into an OAuth 2.1 authorization server. External
applications (for example MCP clients or third-party tools) obtain a token from Dolibarr
with the authorization code flow and PKCE, then call the REST API or the MCP endpoint
with it. Access is always limited to the rights of the user who approved the grant.

HTTPS is required for every endpoint. Plain HTTP is refused unless the hidden development
constant `OAUTHSERVER_ALLOW_HTTP` is set.

## Endpoints

Issuer: `<Dolibarr root URL>/oauthserver`

| Endpoint | Path | Purpose |
|---|---|---|
| Authorization | `authorize.php` | User consent page, returns an authorization code (PKCE S256 required) |
| Token | `token.php` | Exchanges a code or a refresh token for tokens |
| Revocation | `revoke.php` | Revokes an access or refresh token (RFC 7009) |
| Registration | `register.php` | Dynamic client registration (RFC 7591), only when dynamic client registration is enabled |
| Metadata | `metadata.php` | Authorization server metadata (RFC 8414) |

## Scopes

| Scope | Meaning |
|---|---|
| `api` | Token accepted by the REST API |
| `mcp` | Token accepted by the MCP endpoint |
| `read` | Read-only access (implicit when `write` is absent) |
| `write` | Allows writes (implies `read`) |
| `offline_access` | A refresh token is issued |

A grant must contain `api` or `mcp`.

## Discovery (`.well-known`)

Clients fetch `https://<host>/.well-known/oauth-authorization-server/oauthserver`. PHP
inside `htdocs/oauthserver/` cannot serve that path, so add one of these rules to the
web server of the host root:

Apache:

```apache
RewriteEngine On
RewriteRule ^/?\.well-known/oauth-authorization-server/oauthserver/?$ /oauthserver/metadata.php [L]
```

Nginx:

```nginx
location = /.well-known/oauth-authorization-server/oauthserver {
    rewrite ^ /oauthserver/metadata.php last;
}
```

The Apache rule above escapes only the dots, which is what the module generates. The
module setup page prints the exact rules for your instance.

If Dolibarr is installed under a sub-path (for example `/dolibarr`), the rule goes at the
host root with the sub-path inserted: `/.well-known/oauth-authorization-server/dolibarr/oauthserver`.

## Using the token

Send the access token in the `Authorization` header. Its format is `dolat_` followed by
random characters:

```
Authorization: Bearer dolat_...
```

Do not use `DOLAPIKEY` for OAuth tokens. Tokens are stored hashed, so a lost token cannot
be displayed again; revoke it and issue a new one.
