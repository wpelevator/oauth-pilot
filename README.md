# OAuth Pilot

An OAuth 2.1 authorization server for WordPress, built with WordPress and PHP primitives and no runtime OAuth, JWT or cryptography dependency.

The concrete goal is that an agent MCP client — a Claude or ChatGPT connector, a local agent CLI — can point at a WordPress site, register itself, have a human approve the connection once, and keep working from then on.

## What it is

- OAuth 2.1 authorization code grant with mandatory PKCE `S256`.
- Refresh tokens with rotation and reuse detection.
- Public clients (`token_endpoint_auth_method=none`) and confidential clients using `client_secret_basic` or `client_secret_post`.
- RFC 7591 Dynamic Client Registration, off by default, with an optional allow-list of redirect URI hosts. Deprecated by MCP as of the 2026-07-28 specification and kept as a backward-compatible fallback for connectors that still need it, so a new site exposes no unauthenticated endpoint that writes client rows.
- Client ID Metadata Documents (CIMD), the MCP 2026-07-28 replacement for DCR: the client_id is an HTTPS URL, and the server fetches a client metadata document from that URL, validates it, and caches it. See [Client ID Metadata Documents](#client-id-metadata-documents).
- RFC 8414 authorization server metadata and RFC 9728 protected resource metadata.
- RFC 8707 resource indicators: every token is bound to exactly one audience.
- RFC 9207 `iss` on every authorization response.
- RFC 7009 token revocation.
- A bearer token validation API other plugins call to protect their own endpoints.

## What it is not

- Not an OpenID Connect provider. No ID tokens, UserInfo, JWKS or login federation.
- Not a JWT issuer. Access tokens are opaque, which makes them revocable.
- Not an OAuth client, and it never proxies tokens to upstream APIs.
- Not a replacement for roles and capabilities. A scope narrows a token; WordPress capabilities still decide what the represented user may do. OAuth Pilot can never grant a user a capability they do not already have.
- Implicit, password, client credentials and device grants are not implemented.

Deferred to a later release: token introspection (RFC 7662), a security event log, and subdirectory or multisite issuers.

## Requirements

WordPress 6.6, PHP 7.4, HTTPS, and **pretty permalinks** — the well-known discovery documents are served through rewrite rules.

The issuer works best at the root of its domain. RFC 8414 itself supports path-based issuers — for issuer `https://host/path` the metadata document lives at `https://host/.well-known/oauth-authorization-server/path`, with the issuer path appended *after* the well-known segment. The catch is placement, not the spec: a plain subdirectory install cannot route that root-level path into WordPress with its own rewrite rules, so the settings screen warns and suggests a server-level rewrite or proxy rule, or a root install. On a subdirectory multisite network the root-level request does reach WordPress but resolves to the main site of the network, so subdirectory sub-sites cannot serve their own metadata yet; subdomain sub-sites have path-less issuers and work. The settings screen warns when a subdirectory issuer is detected, and the plugin never publishes metadata at a convenient but non-conforming URL instead.

## Test playground

The package includes a loopback-only dummy OAuth client for exercising a site from a browser. It discovers the server metadata, prepares a dynamic, CIMD, or pre-registered client, starts a real authorization and consent flow with PKCE, exchanges the callback for tokens, and can refresh, replay, revoke, or use those tokens against a REST route. All client and site configuration is editable in the page.

Start the repository's Docker environment, activate and configure OAuth Pilot on the target site, then run:

```sh
npm run dev-client --workspace=@wpelevator/oauth-pilot
```

Open `http://127.0.0.1:9925`. The default values target `https://oauth.basement.localhost`; replace the site and resource URLs in the page to use another OAuth Pilot installation. A remote installation with publicly trusted HTTPS does not require Docker, although the local CIMD fixture is specifically integrated with this repository's Docker WordPress environment.

The callback listens on `http://127.0.0.1:9925/callback`. For a pre-registered client, use that exact redirect URI when creating the client in WordPress and paste the resulting credentials into the page. For DCR, press **Register (DCR)**; dynamically registered clients are always public, so the playground uses `token_endpoint_auth_method=none`. For CIMD, press **Enable CIMD**; the playground serves the metadata document over a temporary self-signed HTTPS listener and installs a local-only must-use plugin that permits WordPress to fetch it. Press **Disable CIMD**, **Reset session**, or stop the playground normally to remove that helper.

Set `DEV_CLIENT_PORT`, `DEV_CLIENT_CIMD_PORT`, or `DEV_CLIENT_CIMD_HOST` before starting the command to override the two listener ports or the hostname WordPress uses to reach the CIMD listener. If `DEV_CLIENT_PORT` changes, register the matching callback URL shown in the playground log.

## Endpoints

| URL | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource[/<path>]` | RFC 9728 resource metadata. |
| `/.well-known/oauth-authorization-server[/<issuer-path>]` | RFC 8414 server metadata. |
| `/wp-json/oauth-pilot/v1/authorize` | Authorization request. |
| `/wp-json/oauth-pilot/v1/token` | Token and refresh grants. |
| `/wp-json/oauth-pilot/v1/register` | Dynamic client registration. |
| `/wp-json/oauth-pilot/v1/revoke` | Token revocation. |

The login and consent screen lives on `wp-login.php` and is deliberately not advertised: it is the only step of the flow that reads a WordPress cookie.

The four protocol routes are dispatched anonymously. WordPress cookie authentication and Application Passwords are both disabled for exactly those routes, so a logged-in browser session can never change a protocol response and `client_secret_basic` cannot collide with an Application Password.

## Connecting an agent client

**With a Client ID Metadata Document (recommended).** The client hosts its own registration document at an HTTPS URL and uses that URL as its `client_id`. Give the client the site URL and it does the rest — no registration request, nothing to configure. This is the mechanism the MCP 2026-07-28 specification recommends; see [Client ID Metadata Documents](#client-id-metadata-documents).

**With dynamic registration.** The client discovers the metadata, registers itself through RFC 7591, and sends the user to the consent screen. Grant types and response types are narrowed to the ones this server runs, exactly as for a metadata document, and RFC 7591 has the registration response report back what was actually registered. Deprecated by MCP since 2026-07-28 and kept as a fallback for clients that do not support metadata documents yet.

**With a pre-registered client.** Under **Settings → OAuth Pilot → Clients**, add a client with the exact callback URL the connector documents. Choose *Confidential* if the connector asks for a client secret; the secret is shown once and only its SHA-256 hash is stored. Choose the authentication method the connector uses — some send credentials in the `Authorization` header (`client_secret_basic`), others in the request body (`client_secret_post`).

Either way the user approving the connection needs the capability behind each requested scope, and every request the client later makes still goes through normal WordPress capability checks.

A scope request is narrowed the same way, because one client sends one scope string to every server it talks to. Scopes this server never registered — `offline_access`, the OpenID Connect set — and scopes belonging to a different resource than the one being requested are ignored, as RFC 6749 permits, leaving the scopes that can actually be granted. The granted set is what the consent screen shows and what the token response reports, so a client is always told what it received. Only a request where nothing at all can be granted is refused, with `invalid_scope` naming the scopes the resource does support.

## Client ID Metadata Documents

### How the standard works

Client ID Metadata Documents (CIMD, `draft-ietf-oauth-client-id-metadata-document`) remove the registration round trip from OAuth. Instead of the server handing out a client ID, the client publishes a JSON document describing itself at an HTTPS URL it controls, and uses that URL as its `client_id` in every authorization and token request:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://127.0.0.1:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

When an authorization request arrives with a URL-shaped `client_id`, the authorization server fetches the document from exactly that URL and validates it. The request's `redirect_uri` must exactly match one of the `redirect_uris` the document declares. The document's `client_id` must match the URL it was fetched from, so a document published anywhere cannot impersonate a client identified elsewhere.

The trust model is the origin that serves the document. Whoever controls `app.example.com` decides what clients that origin can register, and the authorization code is only ever delivered to a callback published on that same origin. What it proves is control of an origin — not the vendor's brand: `client_name` and every other field are self-asserted, and no signature or third party is involved.

Because the document is fetched from a public URL it cannot carry a shared secret. A CIMD client is always a public client (`token_endpoint_auth_method=none`), which is safe under OAuth 2.1's mandatory PKCE: the code is useless to an intercepted redirect without the verifier that never leaves the client. Confidential CIMD clients would require asymmetric client authentication (`private_key_jwt`, mTLS), which OAuth Pilot does not implement.

The MCP 2026-07-28 specification formally deprecates Dynamic Client Registration in favor of this mechanism. Clients that support everything pick, in order: pre-registered credentials, then CIMD when the authorization server advertises it, then DCR as a fallback.

### How OAuth Pilot implements it

When enabled — it is on by default, next to DCR — OAuth Pilot adds `client_id_metadata_document_supported: true` to its RFC 8414 metadata. An authorization request whose `client_id` is an HTTPS URL then takes the CIMD path:

1. The URL must be a proper `https` URL with a path, no fragment and no userinfo, and no longer than `max_metadata_url_length` (512 characters).
2. The client row is looked up by the SHA-256 hash of the URL. A cached document that has not expired answers immediately.
3. On a miss or an expired cache entry, the server fetches the document — and *only* the server does; the browser never contacts the client URL.
4. The response must be HTTP 200, `application/json`, at most `max_document_bytes` (32 KB), and valid JSON with a `client_id` that matches the fetched URL exactly. `client_name` and `redirect_uris` are required, and `token_endpoint_auth_method` must be `none`. A metadata document is published once for every authorization server its client talks to, so it routinely advertises capabilities this one does not implement. Grant types other than `authorization_code` and `refresh_token`, and response types other than `code`, are therefore dropped rather than treated as a fatal document error — the registration keeps the ones that work, and is refused only when nothing usable is left, meaning no `authorization_code` grant or no `code` response type. Dropping them concedes nothing, because the token endpoint dispatches from its own allowlist rather than from what a client registered. The same sanitization limits as dynamic registration apply, and the `oauth_pilot__client_registration_metadata` filter runs over the normalized document.
5. The validated client is stored with source `cimd`. The generated `op_…` identifier stays internal; everywhere a human sees a client ID — the consent screen, the clients table — the metadata URL is shown instead, because the URL is the actual trust anchor. The consent screen also carries a notice that the registration is self-published.

**Network guards.** Fetching attacker-chosen URLs is the new attack surface CIMD opens, so every fetch is guarded: redirects are never followed (the trust anchor is the origin of the `client_id` URL, not wherever it points next), the fetch times out after 5 seconds, the host must resolve to public IP addresses only — loopback, private, link-local and reserved ranges, and `.local` names, are refused before any request is made, with IP literals checked directly — and fetches are rate limited per hashed client IP, per metadata host, and per site. A site-wide cap on active CIMD clients bounds the table. Failures are recorded as `cimd_fetch_failed` (with the reason), `cimd_rate_limited` and `cimd_quota_exceeded` security events.

Two residual risks are worth knowing about. DNS rebinding — a hostile host answering the pre-fetch resolution with a public address and the fetch itself with an internal one — is mitigated by resolving once and checking every resolved address, but a determined adversary with a short-TTL DNS wedge is best met with network-level egress filtering on the WordPress host. And a hostile document server can waste server time; the fetch timeout, size cap and rate limits bound that.

**Caching.** The document is cached honoring HTTP cache headers: `Cache-Control: max-age` (or `s-maxage`, or `Expires`), clamped between 5 minutes and 24 hours, with a 1 hour default when the server sends no usable headers — so a hostile document can neither pin itself in cache forever nor force a fetch on every request. An expired document is re-fetched on the next authorization request; if that re-fetch fails, a document younger than 7 days keeps serving, an older one is dropped and the authorization fails with `invalid_client`. Token and revocation requests never fetch: they resolve from the cache only, so one authorization flow is always tied to one client row even if the document changes mid-flight. The stored client snapshot inside the authorization freezes the redirect URIs an in-flight code can use.

**Revocation and cleanup.** Administrators revoke a CIMD client like any other from the clients table or `wp oauth-pilot client-revoke`. A revoked CIMD client stays revoked even if its document comes back online and re-validates. Like dynamically registered clients, CIMD clients that never complete an authorization are deleted after 24 hours, and inactive ones holding no live tokens after 90 days.

**Turning it off or restricting it.** The `oauth_pilot__cimd_enabled` filter disables CIMD while keeping DCR and pre-registered clients; `oauth_pilot__cimd_limits` adjusts every quota and cap listed above. Two further filters exist for development and testing, and production sites should leave both untouched: `oauth_pilot__cimd_resolved_ips` overrides DNS resolution for a metadata host (the returned addresses still go through the public-range check), and `oauth_pilot__cimd_url_allowed` short-circuits all network checks for a specific document URL — the escape hatch the e2e harness uses to serve a fixture document.

## The flow

1. The client requests a protected resource without a token and gets a 401 with `WWW-Authenticate: Bearer resource_metadata="…"`.
2. It fetches the resource metadata, then the authorization server metadata.
3. It presents a pre-registered client ID, a client ID metadata document URL, or registers dynamically.
4. It sends the user to `/authorize` with `response_type=code`, `client_id`, an exact registered `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256` and `resource`.
5. OAuth Pilot validates everything before redirecting anywhere, stores the request, and hands the browser an opaque request ID. An untrusted `client_id` or `redirect_uri` produces a local error, never a redirect.
6. The user signs in if needed and approves or denies. The pending request is bound to that user and session.
7. Approval redirects to the exact registered callback with `code`, the original `state`, and `iss`.
8. The client exchanges the code with its PKCE verifier and receives an access token and a refresh token.

**A refresh token is issued for every authorization code grant by default.** Agent clients rarely request `offline_access`, and without a refresh token their connection dies when the first access token expires. A client that does send `offline_access` is not refused for it: the scope is ignored, on the authorization request and on a later refresh that echoes it back. Use `oauth_pilot__issue_refresh_token` to opt out.

## Protecting your own endpoint

Register a resource and its scopes, then validate the token in your permission layer:

```php
add_action(
	'oauth_pilot__register_resources',
	function ( $resources ) {
		$resources->register(
			[
				'uri'      => rest_url( 'example-mcp/v1/mcp' ),
				'name'     => 'Example MCP Server',
				'scopes'   => [ 'mcp:tools', 'mcp:resources' ],
				'defaults' => [ 'mcp:tools' ],
			]
		);
	}
);

add_action(
	'oauth_pilot__register_scopes',
	function ( $scopes ) {
		$scopes->register(
			[
				'name'           => 'mcp:tools',
				'label'          => 'Use MCP tools',
				'description'    => 'Call tools exposed by this WordPress MCP server.',
				'user_can_grant' => function ( int $user_id ): bool {
					return user_can( $user_id, 'edit_posts' );
				},
			]
		);
	}
);
```

```php
use function WPElevator\OAuth_Pilot\plugin;

$context = plugin()->get_validator()->validate_request(
	rest_url( 'example-mcp/v1/mcp' ),
	[ 'mcp:tools' ]
);

if ( is_wp_error( $context ) ) {
	// Forward the challenge so the client can start discovery.
	header( 'WWW-Authenticate: ' . $context->get_error_data()['www_authenticate'] );
	header( 'Access-Control-Expose-Headers: WWW-Authenticate' );

	return $context;
}

$user_id = $context->get_user_id();
```

`Token\Context` exposes the client ID, user ID, resource, scopes, token ID and expiry, plus `has_scope()` and `has_scopes()`. It never exposes the raw token.

Because audiences are compared exactly, a token minted for the WordPress REST API cannot be used against an MCP endpoint that registers itself as a separate resource, and vice versa. When several registered resources match a URL, the most specific path wins.

## Public API

Services are reached through the namespaced `WPElevator\OAuth_Pilot\plugin()` singleton. OAuth Pilot declares no global functions. `plugin()->get_validator()` returns the `Token\Bearer_Validator` with `validate_request()`, `validate_token()` and `get_challenge()`; `plugin()->get_clients()`, `get_tokens()`, `get_resources()` and `get_scopes()` expose the repositories and registries.

### REST API authentication

Enabling **REST API authentication** makes OAuth Pilot accept bearer tokens on every non-protocol WordPress REST endpoint, including routes registered by plugins. The authentication layer resolves only the request URL. A valid token establishes its represented WordPress user, after which the endpoint's normal permission callback and capability checks still decide whether the request is allowed.

Anonymous `401` and `403` responses advertise the canonical WordPress REST resource metadata URL in `WWW-Authenticate`, and expose that header to browser clients. The resource has one scope, `wp:rest`, meaning “use the WordPress REST API as this user.” It authenticates the represented account but grants no capability by itself; every endpoint still authorizes the request through its normal permission callback. This avoids guessing intent from the HTTP method, since extensible APIs can multiplex read and write operations through the same method. The setting is off by default.

When the official [WordPress MCP Adapter](https://github.com/WordPress/mcp-adapter) is active, OAuth Pilot discovers the registered REST endpoints handled by its HTTP transports and gives each route an endpoint-specific protected resource using the same `wp:rest` scope. This detects custom routes through MCP Adapter's public REST transport contract without treating non-HTTP servers as REST resources. An MCP client connecting to `/wp-json/mcp/mcp-adapter-default-server` therefore receives metadata naming that exact URL as its resource, and a token for the shared `/wp-json/` audience cannot be replayed against it. OAuth Pilot only supplies authentication; MCP Adapter's transport capability check and each ability's permission callback remain the authorization layer. Agent Pilot is not involved.

### Settings

The admin screen at **Settings → OAuth Pilot** has three tabs: **Settings** holds the configuration form, **Clients** holds the registered clients table and the form that adds one, and **Status** reports what the server is currently advertising and serving. The tab is carried in a `tab` query argument, with Settings as the default.

Each setting is stored as its own option rather than one serialized array, so WordPress owns its type, default and sanitizer, and each one is individually readable and writable on `/wp/v2/settings` (which requires `manage_options`). A REST write is validated against the setting's schema — an out-of-range lifetime is rejected with a 400 rather than silently clamped — and then passed through the same sanitizer the admin form uses.

| Option | Type | Default |
| --- | --- | --- |
| `oauth_pilot__dynamic_registration_enabled` | boolean | `false` |
| `oauth_pilot__cimd_enabled` | boolean | `true` |
| `oauth_pilot__dynamic_registration_allowed_redirect_hosts` | string | `''` |
| `oauth_pilot__rest_authentication_enabled` | boolean | `false` |
| `oauth_pilot__access_token_lifetime` | integer | `3600` |
| `oauth_pilot__refresh_token_lifetime` | integer | `2592000` |

The filters below take precedence over the stored values, so infrastructure can pin a setting regardless of what the admin screen holds.

### Configuration filters

| Hook | Purpose |
| --- | --- |
| `oauth_pilot__issuer` | Override the canonical issuer, for a reverse proxy or a dedicated authorization host. |
| `oauth_pilot__endpoint_url` | Override a generated endpoint URL by endpoint name. |
| `oauth_pilot__https_required` | Permit an explicit local development exception. Production must leave this true. |
| `oauth_pilot__access_token_lifetime` | Access token TTL, by client, user, resource and scopes. |
| `oauth_pilot__refresh_token_lifetime` | Refresh token TTL. |
| `oauth_pilot__issue_refresh_token` | Opt out of issuing a refresh token for one grant. |
| `oauth_pilot__authorization_code_lifetime` | Authorization code TTL. |
| `oauth_pilot__admin_capability` | The capability required to manage the server. |
| `oauth_pilot__enable_rest_authentication` | Enable bearer authentication for all non-protocol WordPress REST endpoints. Off by default. |
| `oauth_pilot__cimd_enabled` | Turn Client ID Metadata Document resolution off while keeping DCR and static clients. On by default. |

### Registry and policy hooks

| Hook | Purpose |
| --- | --- |
| `oauth_pilot__register_resources` | Register protected resources. |
| `oauth_pilot__protected_resources` | Filter the final resource list. |
| `oauth_pilot__rest_authentication_resource_uri` | Select the registered resource used to authenticate one REST route. Defaults to the shared WordPress REST resource. |
| `oauth_pilot__mcp_adapter_routes` | Adjust the MCP Adapter route-to-resource map discovered by the optional integration. |
| `oauth_pilot__register_scopes` | Register scope definitions. |
| `oauth_pilot__scopes` | Filter the final scope definitions. |
| `oauth_pilot__user_can_grant_scope` | Contextual policy after a scope's own callback. |
| `oauth_pilot__scope_implies` | Customize scope implication checks. |
| `oauth_pilot__consent_required` | Force renewed consent, or disable remembered consent. |
| `oauth_pilot__redirect_uri_allowed` | Approve a private-use scheme callback. Denied by default. |
| `oauth_pilot__dynamic_registration_enabled` | Turn DCR on, or force it off, whatever the stored setting says. Off by default. |
| `oauth_pilot__dynamic_registration_allowed_redirect_hosts` | Override the redirect URI host allow-list for DCR. Returns an empty array to allow any host. |
| `oauth_pilot__dynamic_registration_limits` | Adjust DCR quotas and size limits. |
| `oauth_pilot__cimd_limits` | Adjust Client ID Metadata Document fetch budgets, size caps and cache bounds. |
| `oauth_pilot__cimd_resolved_ips` | Override DNS resolution for a metadata document host. Development and testing only; production must leave it returning null. |
| `oauth_pilot__cimd_url_allowed` | Short-circuit the network checks for one metadata document URL. Development and testing only; production must leave it returning false. |
| `oauth_pilot__client_registration_metadata` | Filter normalized registration metadata before it is stored. |
| `oauth_pilot__rate_limit_allowed` | Override a rate limit decision, or plug in another backend. |

### Metadata and response filters

| Hook | Purpose |
| --- | --- |
| `oauth_pilot__authorization_server_metadata` | Add metadata fields. Core security capabilities are reapplied afterwards and cannot be falsely advertised or removed. |
| `oauth_pilot__protected_resource_metadata` | Add fields to one resource document. |
| `oauth_pilot__cors_headers` | Customize protocol endpoint response headers. |
| `oauth_pilot__consent_context` | Add display context to the consent screen. |
| `oauth_pilot__bearer_challenge` | Add parameters to a bearer challenge. |

### Lifecycle and event actions

| Hook | Purpose |
| --- | --- |
| `oauth_pilot__client_registered` | A client was created by an administrator or by DCR. |
| `oauth_pilot__client_revoked` | A client and its grants and tokens were revoked. |
| `oauth_pilot__authorization_approved` | A user approved a validated request. |
| `oauth_pilot__authorization_denied` | A user denied a validated request. |
| `oauth_pilot__token_issued` | A token was issued. Receives a redacted record, never the credential. |
| `oauth_pilot__token_revoked` | A token or family was revoked. |
| `oauth_pilot__authorization_code_reuse_detected` | Code reuse triggered defensive revocation. |
| `oauth_pilot__refresh_token_reuse_detected` | Refresh family reuse triggered defensive revocation. |
| `oauth_pilot__bearer_authenticated` | A request was authenticated. Receives `Token\Context`. |
| `oauth_pilot__security_event` | A normalized, redacted security event. |

Filters are extension points, not a way around protocol invariants. Final validation always runs after them for the issuer, endpoint URLs, redirect URIs, resources, scopes, registration metadata and lifetimes.

## WP-CLI

```
wp oauth-pilot status
wp oauth-pilot client-list [--format=table|json|csv|yaml]
wp oauth-pilot client-create "My Connector" --redirect-uri=https://example.com/cb [--confidential] [--auth-method=client_secret_post]
wp oauth-pilot client-revoke <client-id>
wp oauth-pilot client-delete <client-id>
wp oauth-pilot token-revoke [--user=<id>] [--client=<client-id>]
wp oauth-pilot cleanup
```

## Users and revocation

Every user's profile screen has an **Authorized Applications** section listing the applications they approved, with the resource, scopes, last use, and a revoke action. Administrators can revoke any grant. Revocation takes effect immediately: no positive validation result is cached across requests.

## Code layout

Classes live under `php/`, grouped by domain with the namespace mirroring the directory, the way seo-pilot groups `head/` and `sitemaps/`:

| Directory | Namespace | Holds |
| --- | --- | --- |
| `php/` | `WPElevator\OAuth_Pilot` | Plugin, Settings, Schema, Cleanup, Server_Urls, Random, Rate_Limiter, Security_Events |
| `php/client/` | `…\Client` | Client, Clients, Authentication, Registration, Cimd, Redirect_URI |
| `php/authorization/` | `…\Authorization` | Authorization, Authorizations, Service, Consent, PKCE |
| `php/token/` | `…\Token` | Token, Tokens, Service, Context, Bearer_Validator |
| `php/resources/` | `…\Resources` | Protected_Resource, Protected_Resources, Scope, Scopes |
| `php/discovery/` | `…\Discovery` | Metadata, Controller |
| `php/rest/` | `…\Rest` | Controller, Authentication |
| `php/http/` | `…\Http` | Request, Response, Response_Emitter, Form_Body, OAuth_Error, Redirect_Error |
| `php/admin/` | `…\Admin` | Screen, Clients_Table, Profile |
| `php/cli/` | `…\Cli` | Command |

`php/http/` deliberately duplicates agent-pilot's `Request`, `Response` and `Response_Emitter` rather than sharing them through `packages/php/`. OAuth Pilot is specified as dependency-free and standalone, and the two copies have already diverged: this one answers CORS preflight, exposes `WWW-Authenticate`, and treats CORS as a per-response decision instead of always sending `Access-Control-Allow-Origin: *`. Extracting a shared package is a reasonable follow-up once a third plugin needs the same primitives.

## Storage, retention and cleanup

Three tables, per site on multisite:

- `{prefix}oauth_pilot_clients` — registered clients. Secrets stored as SHA-256 hashes only. Clients registered through a Client ID Metadata Document also carry the document URL, its SHA-256 hash for indexed lookup, and the fetch and cache-expiry timestamps.
- `{prefix}oauth_pilot_authorizations` — one row per authorization flow, from pending request through approved code to consumed.
- `{prefix}oauth_pilot_tokens` — access and refresh tokens, with the family ID used for rotation and reuse revocation. Token hashes only.

Default lifetimes: authorization request 10 minutes, code 5 minutes, access token 1 hour, refresh token 30 days. Remembered consent is derived from the user's live tokens rather than a separate table, so revoking a grant also revokes the memory of it.

Cleanup runs hourly (expired authorizations) and daily (expired tokens, self-registered clients — dynamic and metadata document — that never completed an authorization after 24 hours, and inactive ones holding no live tokens after 90 days).

Deactivating the plugin unschedules cleanup and keeps all data. Uninstalling drops the three tables and deletes every `oauth_pilot__` option, the same way the other WP Elevator plugins clean up after themselves.

## Restricting which clients can register

Dynamic registration is unauthenticated and self-asserted: RFC 7591 has no client identity concept, and any caller can claim any `client_name`. What actually binds a client is its redirect URI, because the authorization code is only ever delivered to an exactly matching registered callback. The plugin therefore offers a **redirect URI host allow-list**: set **Settings → OAuth Pilot → Settings → Allowed dynamic client domains** to one hostname per line, for example `claude.ai` and `chatgpt.com`, and dynamic registration only accepts callbacks on exactly those hosts. Hosts match exactly with no wildcards, spaces, commas and semicolons are also accepted as separators, pasted URLs and ports are reduced to their hostname, and anything that is not a plain hostname is dropped. Loopback callbacks (`127.0.0.1`, `::1`, `localhost`) stay allowed so native and CLI agent clients keep working, and administrator created clients are never restricted. Adjust or bypass the list with the `oauth_pilot__dynamic_registration_allowed_redirect_hosts` filter.

An allow-listed host still proves origin, not the vendor: a callback under `claude.ai` can only be received by whoever controls that origin, which is the practical gate for "only the real connector can connect", but `client_name` and other metadata remain self-asserted. Client ID Metadata Documents give clients the same origin-bound identity without needing the allow-list at all — their trust anchor is the origin that serves the document — so the allow-list applies to dynamic registration only.

## Dynamic registration limits

Registration is unauthenticated by design, so it is bounded: 1,000 active dynamic clients per site (an exact count), 10 registrations per hashed IP per hour and 100 per site per hour (best effort), 10 redirect URIs per client, 2 KB per URI, 32 KB per request body, and a length limit on every metadata string. Adjust with `oauth_pilot__dynamic_registration_limits`. Rejected allow-list violations are recorded as a `dynamic_registration_redirect_host_denied` security event.

## Troubleshooting

**Discovery returns 404.** The well-known documents are rewrite rules. Visit Settings → Permalinks to flush them, and make sure the site does not use plain permalinks.

**A client with a URL-shaped client_id fails with `invalid_client`.** That is the Client ID Metadata Document path: the document at the client_id URL could not be fetched, was not JSON, did not match the URL, or was served from a private address. Open the URL in a browser, make sure the WordPress host can reach it (outbound HTTP, DNS), and check the `cimd_fetch_failed` security event for the reason. A client that worked for months and suddenly fails has usually let its document's certificate or hosting lapse — the cached copy is dropped once it is more than 7 days past expiry.

**Metadata is served from a subdirectory.** RFC 8414 places it at the root of the host, before the issuer path — a location a subdirectory install's own rewrite rules cannot reach. The settings screen names the exact URL that has to work; add a server-level rewrite or proxy rule for it, or run the authorization server on a root install.

**The issuer is a subdirectory site on a multisite network.** The root-level metadata URL reaches WordPress but resolves to the main site of the network, so a subdirectory sub-site cannot serve its own metadata yet. Use the main site as the issuer, or give the site its own subdomain.

**The authorize request 403s for a logged-in administrator.** That is `rest_cookie_check_errors()` rejecting a cookie without a `wp_rest` nonce. OAuth Pilot disables it for its own routes; if you see this, another plugin is authenticating REST requests earlier.

**`client_secret_basic` fails with an Application Password error.** Another plugin is reading the `Authorization` header before OAuth Pilot. The isolation covers the four protocol routes only.

**The connection works for an hour, then breaks.** The client is not getting or not storing a refresh token. Check whether `oauth_pilot__issue_refresh_token` was filtered, and that the client registered the `refresh_token` grant.

**A caching layer is serving token responses.** Every response that carries a credential sends `Cache-Control: no-store`; make sure a page cache or CDN is not overriding it for `wp-json`.

## Security reporting

Report vulnerabilities privately to <support@wpelevator.com>. Do not post credentials, tokens, authorization codes, or exploit details in public support channels or issue trackers.
