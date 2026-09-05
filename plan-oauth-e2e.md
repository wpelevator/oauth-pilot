# Plan: OAuth Pilot E2E Client Harness

An end-to-end test harness that drives the plugin the way real clients do: as an OAuth 2.1 / MCP client over HTTP against the local dev site, with a real browser for the login and consent leg. Complements the phpunit suite, which covers the protocol layer exhaustively but never exercises the consent controller, the tokenless challenge, or multisite.

## Context: what the phpunit suite does and does not cover

The phpunit suite (14 files, ~140 tests) already covers the protocol layer deeply: authorize validation, opaque request IDs, local errors without redirects, code single-use, PKCE tampering, refresh rotation and family revocation on reuse, scope ceilings and step-up challenges, revocation, registration quota and allow-lists, and hash-only token storage.

The gaps the e2e harness closes:

- The consent controller (`php/authorization/class-consent.php`) — the only code that reads a WordPress cookie — has no direct tests. The phpunit `complete_authorization()` helper bypasses it by calling `bind_user()` / `approve()` on the service layer. Nonce handling, decision POST routing, session rebinding rejection, `user_can_grant` failure, and remembered consent are all untested.
- No test asserts the `WWW-Authenticate: Bearer resource_metadata="…"` challenge on a tokenless request, which the README flow (step 1) and the MCP auth spec require. Current behavior returns a bare `401 rest_not_logged_in`. A conformance harness would catch this.
- Zero multisite coverage: per-site table prefixes (`wp_7_oauth_pilot_clients`) and per-site settings (`oauth_pilot_settings` in `wp_{blog}_options`) are untested.
- Nothing validates the client experience end to end on a real HTTPS site behind the Caddy proxy.

## Location

`packages/plugins/oauth-pilot/tests/e2e/`, alongside the existing `tests/phpunit/`, so all tests for the plugin live in one place. Dependencies go into the plugin's `package.json` (`@wpelevator/oauth-pilot` is already an npm workspace member, so hoisting and lockfile handling come for free).

The generic, reusable parts (`helpers/wp-cli.ts`, the fetch/CA wrapper, the login-and-storageState helper, the consent page-object pattern) are kept extractor-ready: once a second plugin adopts e2e tests, they move into a shared JS workspace package (e.g. `@wpelevator/e2e-utils`) that all plugins consume. `client.ts` and the scenarios stay plugin-specific.

## Recommended packages

| Package | Role | Why |
| --- | --- | --- |
| [`oauth4webapi`](https://www.npmjs.com/package/oauth4webapi) (panva) | Protocol driver | Spec-exact OAuth 2.1 / Security BCP routines on top of `fetch`: AS and RS metadata discovery, dynamic client registration, PKCE S256, refresh, revocation. No OIDC baggage, no browser assumptions — matches the plugin's deliberate design of keeping consent outside the protocol. |
| [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk) (client) | Conformance check | A real MCP client with a custom `OAuthClientProvider` performs 401 → `WWW-Authenticate` → resource metadata → DCR → PKCE → token → authenticated JSON-RPC. Running this against the site is the definitive "would a real agent connector work" test. It would fail today because of the missing tokenless challenge, which is exactly the point. |
| `@playwright/test` | Test runner + browser leg | Fixtures, parallel workers, trace/screenshot reporting, and the browser automation for login and the consent screen. |

### Decision: own helpers instead of the WordPress e2e packages

`@wordpress/e2e-test-utils-playwright` (the Gutenberg team's Playwright fixture) was considered and rejected for this harness. Its value is the `admin`/`editor` fixtures and `RequestUtils` (authenticated REST via `admin-ajax.php?action=rest-nonce`). We need none of that: the consent screen is a custom `wp-login.php` action with our own page object regardless, setup and teardown go through wp-cli via `docker exec` because `RequestUtils` cannot patch the custom `oauth_pilot_settings` option, and its env-driven login and custom-`baseURL` handling have known rough edges (gutenberg#53277, #70390). The only piece we would use — a logged-in browser session — is roughly 25 lines of Playwright we control fully, including the parts the fixture cannot know: subdomain blog targeting, the Caddy CA, and translation-proof selectors. Revisit if the harness ever grows into a monorepo-wide e2e framework where shared admin-page helpers pay off.

Alternatives considered otherwise: `openid-client` (same author as oauth4webapi, higher level, but OIDC-leaning and the plugin is explicitly not an OIDC provider); hand-rolled `fetch` scripts (no spec guardrails, drifts from the RFCs the plugin advertises).

## Architecture

```
packages/plugins/oauth-pilot/tests/e2e/
  playwright.config.ts   # base URL, storageState via global setup, Caddy CA handling
  global-setup.ts        # seed test user + settings via wp-cli, authenticate admin, save storage state
  helpers/
    auth.ts              # login via wp-login.php, save/load storageState (~25 lines, ours)
    wp-cli.ts            # docker exec wrapper: user/option seeding, apache restart, cleanup
    fetch.mjs            # fetch wrapper: Caddy CA, retry-once-on-502
    consent.ts           # page object: consent screen (render, approve, deny, error states)
  client.ts              # oauth4webapi driver: discovery, DCR, PKCE, grants, revocation
  mcp-conformance.spec.ts# MCP SDK client with an OAuthClientProvider
  flow.spec.ts           # main scenarios, wired to oauth.basement.localhost
  config.ts              # env parsing: site URL, credentials, blog URL, retry/TLS flags
```

The protocol and browser legs stay separable: `client.ts` produces the authorization URL and consumes the callback URL; `helpers/consent.ts` (backed by `helpers/auth.ts`'s authenticated storage state) turns an authorization URL into a callback URL. That mirrors the plugin's own split (protocol routes are cookie-free; consent is the only cookie-reading step).

Playwright-specific notes:

- `helpers/auth.ts` fills the `wp-login.php` form and saves `storageState` per blog URL, so the consent context starts logged in; one spec runs from a logged-out context to assert the anonymous redirect to login.
- The consent page object should locate the approve/deny buttons by their `name="oauth_pilot_decision"` values (`approve` / `deny`), not by label text, so translations don't break the tests.
- Global setup seeds the test user per target blog (`wp user create ... --url=<blog>`), enables `rest_authentication_enabled` on that blog (`wp eval --url=<blog>`), and tears both down in global teardown. Run wp-cli via `docker exec` (never `npm run cli`) so no ephemeral container ever becomes a Caddy upstream.

## Scenarios

Each scenario doubles as a regression test for a phpunit gap.

1. **Happy path (DCR).** Discover both metadata documents → register a public client → build the authorize request (S256, `resource`, `state`) → consent page object approves → assert the callback carries `code`, the exact `state`, and `iss` → exchange with the verifier → call `/wp-json/wp/v2/users/me` with the bearer token → assert the consenting user.
2. **Refresh rotation and reuse detection.** Refresh → new pair; reuse the old refresh token → expect `invalid_grant` and verify the new tokens were also revoked (family kill).
3. **Revocation (RFC 7009).** Revoke the access token → subsequent resource calls get 401.
4. **Scope narrowing.** Register a test resource with `test:read` and `test:write` scopes and routes that explicitly enforce them. Request only `test:read`, then call the route requiring `test:write` → expect 403 with `WWW-Authenticate: Bearer error="insufficient_scope"`, and the route requiring `test:read` still succeeds. The built-in `wp:rest` scope delegates the user’s existing permissions and does not distinguish reads from writes.
5. **Consent denial.** Click deny → callback carries `error=access_denied`, no code.
6. **Consent screen hard errors.** Replayed/expired `request_id`, wrong-session rebinding (two Playwright contexts), and a user without the required capabilities → local error screens, never redirects.
7. **Tokenless challenge.** `GET` a protected route without credentials → assert the 401 carries `WWW-Authenticate` with `resource_metadata` pointing at the RFC 9728 document. Currently expected to **fail** — this is the known gap from live testing.
8. **MCP conformance.** Run the MCP SDK client end to end against a resource URL. Currently expected to **fail** at discovery for the same reason.
9. **Multisite.** Run the happy path against a second blog on the network to prove per-site table prefixes and per-site settings behave (e.g. bearer auth enabled on blog A must not leak to blog B).

Negative protocol paths (code replay, wrong verifier, unknown client) are already exhaustive in phpunit; the harness includes only a couple as smoke checks, not as the focus.

## Run environments

The harness runs on the host by default and can run inside the Docker network for CI. Both target the same site; `DEV_URL` from the repo `.env` (default `basement.localhost`, per `docker-compose.yml`) is the single source of truth, so the harness base URL is `https://oauth.${DEV_URL:-basement.localhost}`.

**Host (primary).** macOS resolves `*.localhost` to loopback automatically and Caddy publishes 80/443, so no `/etc/hosts` or resolver setup is needed — verified working without any configuration. Only `npx playwright install chromium` is required once.

**Docker (CI option).** Two facts shape this mode: the `caddy: *.${DEV_URL}` compose labels are Caddy route matchers, not DNS entries, so `oauth.basement.localhost` does not resolve inside the network (verified — only service names resolve); and reaching the site over plain HTTP directly against Apache flips `rest_url()` and the issuer to `http://…`, which breaks OAuth audience semantics. The workable recipe: a CI job or optional compose service running the official Playwright image (browsers preinstalled) attached to the compose network, which (a) resolves the site via `caddy-proxy` with explicit SNI/Host (curl `--resolve`-style or a custom fetch with a fixed host mapping), (b) trusts Caddy's internal CA from `/data/pki/authorities/local/root.crt` in the `caddy-proxy` container, and (c) mounts the repo. The fetch wrapper abstracts the host mapping so only the wrapper changes between modes.

## Environment gotchas (learned during the live manual test)

- **TLS.** Playwright (Chromium) and Node's `fetch` reject the Caddy local-CA certificate. Preferred: `NODE_EXTRA_CA_CERTS` pointing at Caddy's root CA (exportable from the `caddy-proxy` container at `/data/pki/authorities/local/root.crt`) plus the equivalent Playwright option (`ignoreHTTPSErrors` is the fallback, dev-only). For oauth4webapi's `fetch` calls, use an undici dispatcher with the CA loaded.
- **Ephemeral CLI containers poison Caddy.** Every `npm run cli` invocation spawns a `compose run` container that the docker-proxy momentarily adds as an upstream; requests routed to the dead IP return intermittent 502s. Run all wp-cli via `docker exec` and retry a failed HTTP request once after a short delay in `config.ts`'s fetch wrapper.
- **object-cache-pilot's APCu L1 is per-SAPI.** `wp cache flush` from CLI cannot invalidate Apache workers' APCu memory, which served stale `notoptions`/usermeta entries during live testing. Global setup should restart Apache inside the web container (`docker exec ... apachectl restart`) after changing options.
- **Per-site settings.** `oauth_pilot_settings` lives in `wp_{blog}_options`; setup must target the blog with `wp eval --url=<blog>`, not the default blog.
- **Test isolation.** Register a fresh client per run and clean it up (`wp oauth-pilot client-delete --url=<blog>`) in teardown, along with the test user.
- **Login robustness.** The login helper must assert success (redirect away from `wp-login.php`, no `invalid_username`/`incorrect_password` shake) so a wrong test password fails setup with a clear message instead of producing confusing consent failures later.

## Implementation plan

1. **Scaffold.** Add `tests/e2e/` with `playwright.config.ts`, `config.ts`, and devDependencies in the plugin's `package.json` (`oauth4webapi`, `@playwright/test`, `@modelcontextprotocol/sdk` — the latter two can wait until their scenarios). Add `npm run test:e2e` to the plugin workspace. Document setup in the plugin README (a short "End-to-end harness" section: prerequisites, `npx playwright install chromium`, env vars).
2. **Global setup/teardown.** Seed test user + settings per blog via `docker exec` wp-cli, restart Apache, log in via `helpers/auth.ts`, save `storageState`. Teardown deletes the user and any registered clients.
3. **Consent page object.** `consent.ts`: navigate to the authorization URL, assert redirect to the consent screen, interact by `oauth_pilot_decision` value, capture the final `127.0.0.1:9925/callback` navigation, return the URL. Also expose the error-screen assertions for scenario 6. One browser context per session (needed for the two-session rebinding test).
4. **Protocol driver.** `client.ts` wrapping oauth4webapi: `discover()`, `register()`, `buildAuthorizeUrl()`, `exchange()`, `refresh()`, `revoke()`, each returning parsed, assertion-friendly results. Keep it thin — oauth4webapi does the spec work; the driver only adapts WordPress-specific details (scope names, resource URI).
5. **Scenarios 1–4** in `flow.spec.ts`, cleaning up the registered client in teardown.
6. **Scenario 7 + fix.** Add the tokenless-challenge test, confirm it fails, then fix `Rest\Authentication::filter_authenticate_bearer()` to emit the challenge when no credential is present (the plumbing already exists via `get_challenge()` and the `rest_post_dispatch` hook), and re-run the phpunit suite plus the new test.
7. **Scenarios 5–6 (consent hard paths).** Uses the page object from step 3, including the anonymous-redirect assertion and the two-context session test.
8. **Scenario 8 (MCP conformance).** Implement `OAuthClientProvider` backed by the consent page object; wire it to a simple resource URL. Mark it `test.skip` with a link to the challenge issue until scenario 7's fix lands, then unskip.
9. **Scenario 9 (multisite).** Parameterize the config over a base URL; run the happy path twice (default blog and a second blog), asserting isolation of clients, tokens, and settings.
10. **CI wiring.** Decide whether this runs in CI (requires the Docker stack and Playwright browsers) or stays a developer-run command documented in the README; if CI, gate it behind a job that starts `docker compose up` first.

## Open questions

- Fixed test user vs. seed-on-demand: global setup creates it via `wp user create --url=<blog>` and deletes it in teardown (chosen), versus requiring a pre-seeded user documented in the README.
- Callback listener: use a real `http.createServer` on `127.0.0.1:9925` (truest to a connector) or just let Playwright capture the navigation URL (simpler, equivalent for assertions). Start with Playwright capture.
- Whether the harness should also cover confidential clients (`client_secret_basic`/`post`) — phpunit covers the protocol; the browser flow is identical. Low priority.
- If other monorepo plugins adopt e2e tests later, consider extracting `tests/e2e/helpers/` into a shared workspace package before copying it around; the WordPress fixture remains an option for admin-page-heavy suites at that point.
