/** Render the single-page UI. All values come from the live session state. */

function esc( value ) {
	return String( value ?? '' )
		.replace( /&/g, '&amp;' )
		.replace( /</g, '&lt;' )
		.replace( />/g, '&gt;' )
		.replace( /"/g, '&quot;' );
}

function input( name, value, { placeholder = '', hint = '' } = {} ) {
	return `
		<label>
			<span>${ esc( name ) }</span>
			<input name="${ esc( name ) }" value="${ esc( value ) }" placeholder="${ esc( placeholder ) }" />
			${ hint ? `<small>${ esc( hint ) }</small>` : '' }
		</label>`;
}

function badge( label, status = 'off' ) {
	return `<span class="badge ${ status }">${ esc( label ) }</span>`;
}

function staleBadge( stale ) {
	return stale ? badge( 'stale', 'warn' ) : '';
}

function disabledLink( label, disabled ) {
	return disabled ? `<span class="button disabled">${ esc( label ) }</span>` : `<a class="button" href="/authorize">${ esc( label ) }</a>`;
}

export function renderPage( state, csrfToken = '' ) {
	const s = state;
	// Every state-changing route is a POST guarded by this per-process token,
	// so a cross-origin page cannot drive the client by submitting a form at it.
	const csrf = `<input type="hidden" name="csrf" value="${ esc( csrfToken ) }" />`;
	const connected = Boolean( s.tokens?.access_token );
	const usableTokens = connected && ! s.stale.tokens;
	const cimdReady = Boolean( s.cimd );
	const canAuthorize = Boolean( s.clientId && s.discovery && ! s.stale.discovery && ! s.stale.client );
	const resourceStatus = s.resourceMetadata
		? `${ badge( `challenge ${ s.resourceMetadata.probeStatus }`, 'on' ) } ${ staleBadge( s.stale.resource ) }`
		: badge( 'not probed', 'off' );
	const discoveryStatus = s.discovery
		? `${ badge( `metadata via ${ s.discoverySource || 'issuer' }`, 'on' ) } ${ staleBadge( s.stale.discovery ) }`
		: badge( 'not discovered', 'off' );

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OAuth Pilot dev client</title>
<style>
	:root { color-scheme: light dark; }
	* { box-sizing: border-box; }
	body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f6f7f7; color: #1d2327; }
	@media (prefers-color-scheme: dark) { body { background: #1d2327; color: #f0f0f1; } }
	header { background: #1d2327; color: #fff; padding: 14px 24px; display: flex; align-items: center; gap: 14px; }
	header h1 { font-size: 16px; margin: 0; font-weight: 600; }
	header span { opacity: .7; font-size: 12px; }
	header form { margin-left: auto; }
	header button { background: transparent; border-color: #a7aaad; color: #fff; padding: 5px 10px; }
	main { display: grid; grid-template-columns: minmax(440px, 580px) minmax(440px, 1fr); gap: 16px; padding: 16px 24px; align-items: start; }
	@media (max-width: 1100px) { main { grid-template-columns: 1fr; } }
	fieldset, .card { background: #fff; border: 1px solid #dcdcde; border-radius: 6px; padding: 14px 16px; margin: 0 0 16px; }
	@media (prefers-color-scheme: dark) { fieldset, .card { background: #2c3338; border-color: #3c434a; } }
	legend { font-weight: 600; padding: 0 6px; }
	h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; margin: 0; opacity: .75; }
	h3 { font-size: 12px; margin: 18px 0 6px; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
	label { display: block; margin: 8px 0; }
	label span { display: block; font-size: 12px; font-weight: 600; margin-bottom: 2px; }
	label small { display: block; opacity: .65; font-size: 11px; }
	input, select { width: 100%; padding: 6px 8px; border: 1px solid #8c8f94; border-radius: 4px; font: inherit; background: transparent; color: inherit; }
	.row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
	.actions, .card-title { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; align-items: center; }
	.card-title { margin: 0 0 8px; justify-content: space-between; }
	.card-title .actions { margin: 0; }
	button, a.button, span.button { font: inherit; font-weight: 600; padding: 7px 14px; border-radius: 4px; border: 1px solid #2271b1; background: #2271b1; color: #fff; cursor: pointer; text-decoration: none; display: inline-block; }
	button.secondary, a.button.secondary { background: transparent; color: #2271b1; }
	button.danger { background: transparent; color: #b32d2e; border-color: #b32d2e; }
	button:disabled, span.button.disabled { opacity: .4; cursor: not-allowed; }
	form.inline { display: inline-flex; gap: 8px; align-items: end; }
	form.inline label { margin: 0; }
	form.inline input, form.inline select { min-width: 190px; }
	.badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; margin-left: 4px; vertical-align: middle; }
	.badge.on { background: #00a32a; color: #fff; }
	.badge.off { background: #8c8f94; color: #fff; }
	.badge.warn { background: #dba617; color: #1d2327; }
	.badge.bad { background: #b32d2e; color: #fff; }
	pre { background: #1d2327; color: #dcdcde; padding: 10px 12px; border-radius: 4px; overflow: auto; font-size: 12px; max-height: 280px; margin: 8px 0 0; white-space: pre-wrap; overflow-wrap: anywhere; }
	#wire { height: calc(65vh - 90px); min-height: 340px; max-height: none; }
	#log { height: calc(35vh - 95px); min-height: 180px; max-height: none; }
	.muted { opacity: .68; font-size: 12px; }
	.notice { border-left: 4px solid #dba617; background: rgba(219, 166, 23, .12); padding: 8px 10px; font-size: 12px; }
	.inspector { position: sticky; top: 16px; }
	@media (max-width: 1100px) { .inspector { position: static; } }
</style>
</head>
<body>
<header>
	<h1>OAuth Pilot dev client</h1>
	<span>resource discovery, registration, consent, tokens, and API calls</span>
	<form method="post" action="/reset">${ csrf }<button type="submit">Reset playground</button></form>
</header>
<main>
	<div>
		<form method="post" action="/config">${ csrf }
			<fieldset>
				<legend>1 · Discover</legend>
				${ input( 'site_url', s.siteUrl, { placeholder: 'https://oauth.basement.localhost', hint: 'Authorization server issuer used for direct discovery.' } ) }
				${ input( 'protected_url', s.protectedUrl, { hint: 'A concrete endpoint that returns 401 without a token, such as /wp-json/wp/v2/users/me.' } ) }
				${ input( 'resource', s.resource, { hint: 'RFC 8707 audience identifier. This is intentionally the /wp-json API root, not the concrete endpoint above.' } ) }
				<div class="actions">
					<button type="submit" name="do" value="discover_resource">Discover from protected URL</button>
					<button type="submit" name="do" value="discover_issuer" class="secondary">Discover issuer directly</button>
					<button type="submit" name="do" value="save" class="secondary">Save only</button>
				</div>
				<p class="muted">Resource-first discovery follows <code>WWW-Authenticate: Bearer resource_metadata="…"</code>, loads that document, then discovers its authorization server.</p>
				<p>${ resourceStatus } ${ discoveryStatus }</p>
				${ s.resourceMetadata ? `<pre>${ esc( JSON.stringify( s.resourceMetadata.document, null, 2 ) ) }</pre>` : '' }
			</fieldset>

			<fieldset>
				<legend>2 · Client ${ staleBadge( s.stale.client ) }</legend>
				${ input( 'client_name', s.clientName ) }
				<div class="row">
					<label><span>Registration</span><select name="registration"><option value="dcr" ${ s.registration === 'dcr' ? 'selected' : '' }>Dynamic (RFC 7591)</option><option value="cimd" ${ s.registration === 'cimd' ? 'selected' : '' }>Client ID Metadata Document</option><option value="static" ${ s.registration === 'static' ? 'selected' : '' }>Pre-registered</option></select></label>
					<label><span>Client auth</span><select name="auth_method"><option value="none" ${ s.authMethod === 'none' ? 'selected' : '' }>Public (none)</option><option value="client_secret_basic" ${ s.authMethod === 'client_secret_basic' ? 'selected' : '' }>client_secret_basic</option><option value="client_secret_post" ${ s.authMethod === 'client_secret_post' ? 'selected' : '' }>client_secret_post</option></select></label>
				</div>
				${ input( 'client_id', s.clientId, { hint: 'Filled by DCR; paste a pre-registered ID or a CIMD URL.' } ) }
				${ input( 'client_secret', s.clientSecret, { placeholder: 'only for confidential clients' } ) }
				${ input( 'redirect_uri', s.redirectUri, { hint: 'Must match the registration exactly.' } ) }
				<div class="row">${ input( 'scope', s.scope ) }${ input( 'resource_param', s.resourceParam || s.resource, { hint: 'Sent as resource= during authorization and token requests.' } ) }</div>
				<div class="actions">
					<button type="submit" name="do" value="dcr" class="secondary">Register (DCR)</button>
					<button type="submit" name="do" value="cimd_start" class="secondary" ${ cimdReady ? 'disabled' : '' }>Enable CIMD</button>
					<button type="submit" name="do" value="cimd_stop" class="secondary" ${ cimdReady ? '' : 'disabled' }>Disable CIMD</button>
					${ cimdReady ? badge( `CIMD live · fetched ${ s.cimd.fetchCount.n }×`, 'on' ) : '' }
				</div>
				<p class="muted">DCR and CIMD prepare public clients. Client auth and secret apply to pre-registered clients.</p>
			</fieldset>
		</form>

		<fieldset>
			<legend>3 · Authorize ${ staleBadge( s.stale.authorization ) }</legend>
			<p class="muted">Builds the authorization URL with a fresh PKCE challenge and state, then opens the real WordPress login and consent screens.</p>
			<div class="actions">${ disabledLink( 'Start authorization', ! canAuthorize ) }</div>
			${ ! canAuthorize ? '<p class="muted">Load current server metadata and prepare a current client first.</p>' : '' }
			${ s.lastAuthorizeUrl ? `<p class="muted">Last URL:</p><pre>${ esc( s.lastAuthorizeUrl ) }</pre>` : '' }
		</fieldset>

		<fieldset>
			<legend>4 · Tokens ${ connected ? badge( 'connected', 'on' ) : badge( 'no token', 'off' ) } ${ staleBadge( s.stale.tokens ) }</legend>
			${ s.stale.tokens ? '<p class="notice">These tokens belong to an older configuration. They are kept for inspection, but refresh and authenticated API calls are blocked until you authorize again.</p>' : '' }
			<div class="actions">
				<form class="inline" method="post" action="/token/refresh">${ csrf }<label><span>Optional narrower scope</span><input name="scope" value="${ esc( s.refreshScope ) }" placeholder="Leave empty to retain granted scopes" /></label><button type="submit" class="secondary" ${ s.tokens?.refresh_token && ! s.stale.tokens ? '' : 'disabled' }>Refresh</button></form>
			</div>
			<div class="actions">
				<form class="inline" method="post" action="/token/reuse">${ csrf }<button type="submit" class="secondary" ${ s.lastRefreshToken ? '' : 'disabled' }>Replay old refresh</button></form>
				<form class="inline" method="post" action="/token/revoke">${ csrf }<label><span>Token to revoke</span><select name="token_type"><option value="access_token">Access token</option><option value="refresh_token" ${ s.tokens?.refresh_token ? '' : 'disabled' }>Refresh token</option></select></label><button type="submit" class="danger" ${ connected ? '' : 'disabled' }>Revoke</button></form>
				${ s.accessTokenRevoked ? badge( 'access revoked', 'bad' ) : '' }${ s.refreshTokenRevoked ? badge( 'refresh revoked', 'bad' ) : '' }
			</div>
			${ s.tokens ? `<pre>${ esc( JSON.stringify( redactTokens( s.tokens ), null, 2 ) ) }</pre>` : '' }
		</fieldset>

		<fieldset>
			<legend>5 · Call the API</legend>
			<form method="post" action="/api">${ csrf }
				<div class="row"><label><span>Method</span><select name="method"><option>GET</option><option>POST</option><option>DELETE</option></select></label>${ input( 'path', s.apiPath || '/wp-json/wp/v2/users/me', { hint: 'Relative to the site.' } ) }</div>
				<div class="actions"><button type="submit" ${ usableTokens ? '' : 'disabled' }>Send with bearer token</button><button type="submit" name="anonymous" value="1" class="secondary">Send without token</button></div>
			</form>
			${ s.lastApi ? `<p class="muted">HTTP ${ esc( s.lastApi.status ) } ${ esc( s.lastApi.challenge ? `· WWW-Authenticate: ${ s.lastApi.challenge }` : '' ) }</p><pre>${ esc( s.lastApi.body ) }</pre>` : '' }
		</fieldset>
	</div>

	<div class="card inspector">
		<div class="card-title">
			<h2>Wire inspector ${ s.revealSecrets ? badge( 'secrets visible', 'bad' ) : badge( 'redacted', 'on' ) }</h2>
			<div class="actions"><form class="inline" method="post" action="/wire/reveal">${ csrf }<input type="hidden" name="reveal" value="${ s.revealSecrets ? '0' : '1' }" /><button type="submit" class="secondary">${ s.revealSecrets ? 'Hide secrets' : 'Reveal secrets' }</button></form><form class="inline" method="post" action="/log/clear">${ csrf }<button type="submit" class="secondary">Clear logs</button></form></div>
		</div>
		<pre id="wire"></pre>
		<h3>Event log</h3>
		<pre id="log"></pre>
		<p class="muted">Newest first. Requests and responses refresh every two seconds. Reveal affects this local session only; the event log and terminal remain redacted.</p>
	</div>
</main>
<script>
	async function poll() {
		try {
			const [ wire, log ] = await Promise.all( [ fetch( '/wire' ), fetch( '/log' ) ] );
			document.getElementById( 'wire' ).textContent = await wire.text();
			document.getElementById( 'log' ).textContent = await log.text();
		} catch ( e ) { /* server restarting */ }
	}
	poll();
	setInterval( poll, 2000 );
</script>
</body>
</html>`;
}

function redactTokens( tokens ) {
	const redacted = { ...tokens };
	for ( const key of [ 'access_token', 'refresh_token' ] ) {
		if ( typeof redacted[ key ] === 'string' ) {
			redacted[ key ] = `${ redacted[ key ].slice( 0, 8 ) }… (${ redacted[ key ].length } chars)`;
		}
	}
	return redacted;
}
