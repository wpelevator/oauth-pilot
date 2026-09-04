# Changelog

## Unreleased

## 0.5.0 (2026-09-05)

- Fixed the consent screen refusing an entire authorization request when the approving user could not grant every scope in it, which locked lower-privileged users out of connections they could have made. An MCP client following the specification's scope selection strategy requests every scope the resource advertises, so a site offering both a read and a write scope turned away everyone without the write capability, dead-ending on "Your account is not allowed to grant the requested permissions" instead of connecting them read-only. Scopes the user cannot grant are now dropped at consent, as RFC 6749 permits for the request as a whole, and only a user who can grant nothing at all is refused. The narrowed set is what the screen lists, what the authorization code carries and what the token response reports.
- `oauth_pilot__user_can_grant_scope` returning false now drops that one scope from the grant instead of failing the whole request. A policy that must refuse the connection outright can deny every scope.

## 0.4.0 (2026-09-04)

- Fixed REST API authentication answering for routes that register their own protected resource, which rejected a valid token as issued for a different resource before the route ever ran. An MCP server nested under `wp-json` with its own scopes was unreachable with the very token OAuth Pilot had just minted for it, so a client completed consent and then failed on its first authenticated call. Authentication now resolves the deepest registered audience for the request URL and stands aside when that audience is not the shared REST one, leaving the route to authenticate its own tokens.
- Fixed a token minted for the shared `wp:rest` audience establishing its user on a route belonging to a different registered audience.

## 0.3.0 (2026-09-04)

- Fixed client registration refusing an entire client id metadata document because it advertised an extension grant this server does not implement, which blocked Claude and any other client whose published document lists `urn:ietf:params:oauth:grant-type:jwt-bearer`. Unsupported grants are now dropped and the supported ones kept, as RFC 7591 allows, and a client left without `authorization_code` is still refused.
- Fixed registration refusing a client that advertises response types beyond `code`, such as the OpenID Connect ones a client lists in the single document it publishes for every authorization server. Only `code` is registered, and a client that cannot use it is still refused.
- Fixed an authorization request being refused outright when its scope string carried anything this server had not registered, so a client asking for `offline_access` to obtain a refresh token, or sending the OpenID Connect scopes out of habit, could not connect at all. A scope request is now narrowed to what the resource and the client's own ceiling allow, as RFC 6749 permits, and refused with `invalid_scope` only when nothing can be granted, naming the scopes the resource does support. Scopes belonging to another resource are narrowed the same way instead of failing a request that also asked for grantable ones.
- Fixed a refresh request being refused when it echoed back a scope that had been ignored when the grant was made. Unregistered scopes are dropped before the check that a refresh may narrow but never widen a grant, which is unchanged.

## 0.2.1 (2026-09-04)

- Fixed the distribution build to include OAuth Pilot's Composer autoloader, preventing activation failures in standalone plugin installs.

## 0.2.0 (2026-09-04)

- Initial release: OAuth 2.1 authorization server with authorization code + PKCE S256, refresh token rotation, Dynamic Client Registration, token revocation, RFC 8414 and RFC 9728 discovery metadata, and a bearer token validation API for MCP servers and other protected resources.
- Client ID Metadata Documents (CIMD), the client registration mechanism the MCP 2026-07-28 specification recommends in place of the now-deprecated dynamic client registration: an HTTPS URL as the client_id whose self-published metadata document the server fetches, validates, caches and rate limits. Advertised as `client_id_metadata_document_supported` in the authorization server metadata; configurable with the `oauth_pilot__cimd_enabled` and `oauth_pilot__cimd_limits` filters. Schema version 2 adds the metadata URL, hash and cache timestamps to the clients table and is installed automatically.
- Browser-based OAuth client playground for manually exercising discovery, DCR, CIMD, consent, PKCE token exchange, refresh rotation, revocation, and authenticated REST requests against a WordPress site.
- Fixed CIMD response-header parsing for live WordPress HTTP responses, whose headers use a case-insensitive dictionary rather than the arrays returned by test fixtures.
- Settings are stored as one option per setting (`oauth_pilot__*`) instead of a single serialized array, each registered with its own type, default, sanitizer and REST schema, so every one of them is individually readable and writable on `/wp/v2/settings`.
- Dynamic client registration now ships disabled. It is deprecated in favor of Client ID Metadata Documents, and a new site no longer exposes an unauthenticated endpoint that writes client rows.
- CIMD metadata documents are capped at 5 KB and fetched through `wp_safe_remote_get()` with `limit_response_size`, so an unauthenticated authorization request cannot make the site buffer a large response.
- A CIMD refresh that changes redirect URIs or grant types now revokes the client's tokens and pending authorizations, so a reassigned or compromised client domain cannot inherit consent granted to the previous controller. Expired metadata is never served after a failed refetch.
- The consent screen leads with the application's self-claimed name attributed as such - `Application named “Name” wants to access this site as you (user with role Role)` - and names the account and role the grant would be made with. The client ID metadata document and loopback redirect notices are gone; only the warning that a dynamically registered client was never reviewed by an administrator remains, carrying core's own `notice-error` class. Permissions requested is a real heading, the screen stops duplicating core's `backtoblog` element ID, and long client identifiers wrap inside the form instead of overflowing it. Its styles load from `css/consent.css` and add no colors, so whatever a site does to restyle its login page continues to apply.
- Rate limit windows are anchored at the first attempt instead of being extended on every request, which previously let continued requests keep a public client blocked indefinitely. With a persistent object cache the counter is now an atomic increment.
- Authorization requests are rate limited per IP, per client and site-wide, with an exact quota on pending rows.
- Optional REST bearer authentication uses the canonical WordPress REST resource and one `wp:rest` authentication scope for every non-protocol REST route, including routes registered by plugins. It advertises resource metadata on authentication errors, establishes the represented WordPress user, and leaves authorization to each endpoint's normal permission callback instead of inferring access from the HTTP method.
- The optional MCP Adapter integration discovers registered REST transport endpoints and gives each route its own OAuth audience while sharing the authentication-only `wp:rest` scope. OAuth Pilot establishes the WordPress user; MCP Adapter keeps responsibility for transport and ability authorization.
- The dev client validates a per-process CSRF token and the request origin on every state-changing route.
- The admin screen is split into standard WordPress nav tabs: **Settings** carries the configuration form, **Clients** carries the clients table and the form that adds one, and **Status** reports what the server advertises and serves. Settings is the default tab, and client actions return to the Clients tab.
