/**
 * OAuth Pilot dev client — an interactive OAuth 2.1 client for manual testing.
 *
 * Serves a small web UI on loopback where you point at any OAuth Pilot site,
 * register a client (DCR, CIMD or pre-registered), and run the full dance:
 * discovery → authorize (real login + consent in your browser) → callback →
 * token exchange → API calls → refresh / reuse / revoke. Every protocol step
 * is logged to the page.
 *
 * Run: npm run dev-client --workspace=@wpelevator/oauth-pilot
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import express from 'express';
import * as oauth from 'oauth4webapi';
import {
	HttpClient,
	createPkce,
	ensureSelfSignedCert,
	extractResourceMetadataUrl,
	installCimdMuPlugin,
	loadCaddyCa,
	randomState,
	redactHttpTrace,
	redactSecrets,
	removeCimdMuPlugin,
} from './lib.mjs';
import { renderPage } from './page.mjs';

const PORT = Number( process.env.DEV_CLIENT_PORT || 9925 );
const CIMD_PORT = Number( process.env.DEV_CLIENT_CIMD_PORT || 8643 );
const CIMD_HOST = process.env.DEV_CLIENT_CIMD_HOST || 'host.docker.internal';

// The UI is unauthenticated on loopback, so any page in the same browser could
// otherwise POST at it: submitting a cross-origin form here would reconfigure
// the client, trigger server side fetches, or spend a live access token. A
// per-process token in every form, plus an origin check, keeps that out.
const CSRF_TOKEN = randomBytes( 32 ).toString( 'hex' );
const ALLOWED_HOSTS = new Set( [ `127.0.0.1:${ PORT }`, `localhost:${ PORT }`, `[::1]:${ PORT }` ] );

// ---------------------------------------------------------------------------
// Session state (single-user tool, one in-memory session)
// ---------------------------------------------------------------------------

function initialState() {
	return {
		siteUrl: 'https://oauth.basement.localhost',
		resource: 'https://oauth.basement.localhost/wp-json',
		protectedUrl: 'https://oauth.basement.localhost/wp-json/wp/v2/users/me',
		clientName: 'OAuth Pilot dev client',
		registration: 'dcr',
		authMethod: 'none',
		clientId: '',
		clientSecret: '',
		redirectUri: `http://127.0.0.1:${ PORT }/callback`,
		scope: 'wp:rest',
		resourceParam: '',
		discovery: null, // oauth.AuthorizationServer
		discoverySource: '',
		resourceMetadata: null,
		lastAuthorizeUrl: '',
		pending: null, // { pkce, state, clientId, clientSecret, authMethod }
		tokens: null,
		lastRefreshToken: null,
		refreshScope: '',
		accessTokenRevoked: false,
		refreshTokenRevoked: false,
		lastApi: null,
		cimd: null, // { server, fetchCount, clientIdUrl }
		revealSecrets: false,
		stale: { resource: false, discovery: false, client: false, authorization: false, tokens: false },
	};
}

const state = initialState();

const logLines = [];
const wireEntries = [];

function log( message, data ) {
	const time = new Date().toLocaleTimeString( 'en-GB', { hour12: false } );
	let line = `[${ time }] ${ message }`;
	if ( data !== undefined ) {
		line += `\n${ typeof data === 'string' ? data : JSON.stringify( redactSecrets( data ), null, 2 ) }`;
	}
	logLines.unshift( line );
	if ( logLines.length > 300 ) {
		logLines.length = 300;
	}
	console.log( line );
}

// ---------------------------------------------------------------------------
// HTTP plumbing: oauth4webapi over the local CA + the 502 retry the dev
// proxy needs, and the same client for the API-call section.
// ---------------------------------------------------------------------------

const ca = loadCaddyCa();
const http = new HttpClient( ca );

function plainHeaders( headers = {} ) {
	if ( headers instanceof Headers ) {
		return Object.fromEntries( headers.entries() );
	}
	return Object.fromEntries( Object.entries( headers ).map( ( [ key, value ] ) => [ key, Array.isArray( value ) ? value.join( ', ' ) : String( value ) ] ) );
}

function requestBody( body ) {
	if ( body === undefined || body === null ) {
		return '';
	}
	if ( typeof body === 'string' ) {
		return body;
	}
	if ( body instanceof URLSearchParams ) {
		return body.toString();
	}
	return String( body );
}

function recordWire( label, started, request, response ) {
	wireEntries.unshift( {
		time: new Date().toISOString(),
		label,
		durationMs: Date.now() - started,
		request,
		response,
	} );
	if ( wireEntries.length > 100 ) {
		wireEntries.length = 100;
	}
}

async function protocolFetch( url, options = {} ) {
	const started = Date.now();
	const request = {
		method: options.method || 'GET',
		url: String( url ),
		headers: plainHeaders( options.headers ),
		body: requestBody( options.body ),
	};
	const response = await http.fetch( url, options );
	recordWire( 'OAuth protocol', started, request, {
		status: response.status,
		headers: plainHeaders( response.headers ),
		body: await response.clone().text(),
	} );
	return response;
}

async function tracedRequest( label, method, url, options = {} ) {
	const started = Date.now();
	const response = await http.request( method, url, options );
	recordWire( label, started, {
		method,
		url,
		headers: plainHeaders( options.headers ),
		body: requestBody( options.body ),
	}, {
		status: response.status,
		headers: plainHeaders( response.headers ),
		body: response.body,
	} );
	return response;
}

const protocolRequestOptions = {
	[ oauth.customFetch ]: protocolFetch,
};

// ---------------------------------------------------------------------------
// oauth4webapi client auth, chosen by the UI
// ---------------------------------------------------------------------------

function clientAuth( client = state ) {
	if ( client.authMethod === 'client_secret_basic' ) {
		return oauth.ClientSecretBasic( client.clientSecret );
	}
	if ( client.authMethod === 'client_secret_post' ) {
		return oauth.ClientSecretPost( client.clientSecret );
	}
	return oauth.None();
}

function currentClient( client = state ) {
	return { client_id: client.clientId };
}

async function discover( issuerValue = state.siteUrl, source = 'issuer' ) {
	const issuer = new URL( issuerValue );
	log( `Discovering authorization server metadata for ${ issuer.origin } …` );
	state.discovery = await oauth
		.discoveryRequest( issuer, { algorithm: 'oauth2', ...protocolRequestOptions } )
		.then( ( r ) => oauth.processDiscoveryResponse( issuer, r ) );
	state.discoverySource = source;
	state.stale.discovery = false;
	log( 'Authorization server metadata', state.discovery );
	return state.discovery;
}

async function discoverFromResource() {
	log( `Probing protected URL without a token: ${ state.protectedUrl }` );
	const probe = await tracedRequest( 'Protected resource probe', 'GET', state.protectedUrl );
	const challenge = probe.headers['www-authenticate'] || '';
	const metadataUrl = extractResourceMetadataUrl( challenge );
	if ( ! metadataUrl ) {
		throw new Error( `The protected URL returned HTTP ${ probe.status } without a Bearer resource_metadata challenge.` );
	}

	log( `Following resource_metadata from the Bearer challenge: ${ metadataUrl }` );
	const response = await tracedRequest( 'Protected resource metadata', 'GET', metadataUrl, { headers: { Accept: 'application/json' } } );
	if ( response.status !== 200 ) {
		throw new Error( `Protected resource metadata returned HTTP ${ response.status }.` );
	}
	const metadata = JSON.parse( response.body );
	if ( typeof metadata.resource !== 'string' || ! Array.isArray( metadata.authorization_servers ) || ! metadata.authorization_servers[0] ) {
		throw new Error( 'Protected resource metadata must contain resource and at least one authorization_servers entry.' );
	}

	state.resource = metadata.resource.replace( /\/+$/, '' );
	state.resourceMetadata = { url: metadataUrl, challenge, document: metadata, probeStatus: probe.status };
	state.stale.resource = false;
	await discover( metadata.authorization_servers[0], 'resource' );
	log( 'Resource-first discovery completed.', metadata );
}

function configSnapshot() {
	return {
		siteUrl: state.siteUrl,
		resource: state.resource,
		protectedUrl: state.protectedUrl,
		clientName: state.clientName,
		registration: state.registration,
		authMethod: state.authMethod,
		clientId: state.clientId,
		clientSecret: state.clientSecret,
		redirectUri: state.redirectUri,
		scope: state.scope,
		resourceParam: state.resourceParam || state.resource,
	};
}

function changed( before, keys ) {
	return keys.some( ( key ) => before[ key ] !== configSnapshot()[ key ] );
}

function markStaleConfiguration( before ) {
	const issuerChanged = changed( before, [ 'siteUrl' ] );
	const resourceChanged = changed( before, [ 'siteUrl', 'resource', 'protectedUrl' ] );
	const clientDefinitionChanged = changed( before, [ 'clientName', 'registration', 'authMethod', 'clientSecret', 'redirectUri' ] );
	const authorizationChanged = changed( before, [ 'siteUrl', 'resource', 'authMethod', 'clientId', 'clientSecret', 'redirectUri', 'scope', 'resourceParam' ] );

	state.stale.discovery ||= Boolean( state.discovery && issuerChanged );
	state.stale.resource ||= Boolean( state.resourceMetadata && resourceChanged );
	state.stale.client ||= Boolean( state.clientId && state.registration !== 'static' && clientDefinitionChanged );
	state.stale.authorization ||= Boolean( ( state.pending || state.lastAuthorizeUrl ) && authorizationChanged );
	state.stale.tokens ||= Boolean( state.tokens && authorizationChanged );
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

const app = express();
app.use( express.urlencoded( { extended: false } ) );

function isAllowedOrigin( value ) {
	if ( ! value ) {
		return true; // Same-origin form posts may omit Origin on older browsers.
	}

	try {
		return ALLOWED_HOSTS.has( new URL( value ).host );
	} catch {
		return false;
	}
}

function matchesCsrfToken( value ) {
	const supplied = Buffer.from( String( value ?? '' ) );
	const expected = Buffer.from( CSRF_TOKEN );

	return supplied.length === expected.length && timingSafeEqual( supplied, expected );
}

app.use( ( req, res, next ) => {
	if ( 'GET' === req.method || 'HEAD' === req.method || 'OPTIONS' === req.method ) {
		return next();
	}

	if ( ! ALLOWED_HOSTS.has( String( req.headers.host || '' ) ) || ! isAllowedOrigin( req.headers.origin ) ) {
		log( `Rejected a ${ req.method } to ${ req.path } from an unexpected origin.` );

		return res.status( 403 ).type( 'text/plain' ).send( 'Cross-origin request rejected.' );
	}

	if ( ! matchesCsrfToken( req.body?.csrf ) ) {
		log( `Rejected a ${ req.method } to ${ req.path } with a missing or stale CSRF token.` );

		return res.status( 403 ).type( 'text/plain' ).send( 'Invalid CSRF token — reload the page and retry.' );
	}

	return next();
} );

app.get( '/', ( req, res ) => {
	res.type( 'html' ).send( renderPage( state, CSRF_TOKEN ) );
} );

app.get( '/log', ( req, res ) => {
	res.type( 'text/plain' ).send( logLines.join( '\n\n' ) );
} );

app.get( '/wire', ( req, res ) => {
	const entries = state.revealSecrets ? wireEntries : wireEntries.map( redactHttpTrace );
	res.type( 'text/plain' ).send( entries.map( ( entry ) => JSON.stringify( entry, null, 2 ) ).join( '\n\n' ) );
} );

app.post( '/log/clear', ( req, res ) => {
	logLines.length = 0;
	wireEntries.length = 0;
	res.redirect( '/' );
} );

app.post( '/wire/reveal', ( req, res ) => {
	state.revealSecrets = req.body.reveal === '1';
	res.redirect( '/' );
} );

app.post( '/config', async ( req, res, next ) => {
	try {
		const b = req.body;
		const doAction = b.do || 'save';
		const before = configSnapshot();

		state.siteUrl = ( b.site_url || '' ).replace( /\/+$/, '' );
		state.resource = ( b.resource || '' ).replace( /\/+$/, '' );
		state.protectedUrl = ( b.protected_url || '' ).trim();
		state.clientName = b.client_name || state.clientName;
		state.registration = b.registration || 'dcr';
		state.authMethod = b.auth_method || 'none';
		state.clientId = ( b.client_id || '' ).trim();
		state.clientSecret = ( b.client_secret || '' ).trim();
		state.redirectUri = ( b.redirect_uri || '' ).trim();
		state.scope = ( b.scope || '' ).trim();
		state.resourceParam = ( b.resource_param || '' ).trim();
		markStaleConfiguration( before );

		if ( doAction === 'cimd_start' ) {
			await startCimd();
		} else if ( doAction === 'cimd_stop' ) {
			await stopCimd();
		} else if ( doAction === 'dcr' ) {
			await registerDcr();
		} else if ( doAction === 'discover_resource' ) {
			await discoverFromResource();
		} else if ( doAction === 'discover_issuer' ) {
			await discover();
		} else {
			log( 'Configuration saved.' );
		}

		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

async function registerDcr() {
	const as = ! state.discovery || state.stale.discovery ? await discover() : state.discovery;
	if ( ! as.registration_endpoint ) {
		throw new Error( 'The authorization server does not advertise a registration endpoint.' );
	}

	state.registration = 'dcr';
	state.authMethod = 'none';
	state.clientSecret = '';
	state.pending = null;
	state.tokens = null;
	state.lastRefreshToken = null;
	state.lastApi = null;
	state.accessTokenRevoked = false;
	state.refreshTokenRevoked = false;
	const metadata = {
		client_name: state.clientName,
		redirect_uris: [ state.redirectUri ],
		grant_types: [ 'authorization_code', 'refresh_token' ],
		response_types: [ 'code' ],
		token_endpoint_auth_method: 'none',
	};
	log( `POST ${ as.registration_endpoint } (dynamic client registration)`, metadata );

	const response = await oauth
		.dynamicClientRegistrationRequest( as, metadata, protocolRequestOptions )
		.then( ( r ) => oauth.processDynamicClientRegistrationResponse( r ) );

	state.clientId = response.client_id;
	if ( response.client_secret ) {
		state.clientSecret = response.client_secret;
	}
	state.stale.client = false;
	state.stale.authorization = false;
	state.stale.tokens = false;
	log( `Registered. client_id = ${ state.clientId }`, response );
}

async function startCimd() {
	if ( state.cimd ) {
		return;
	}

	const clientIdUrl = `https://${ CIMD_HOST }:${ CIMD_PORT }/dev-client/client.json`;
	state.pending = null;
	state.tokens = null;
	state.lastRefreshToken = null;
	state.lastApi = null;
	state.accessTokenRevoked = false;
	state.refreshTokenRevoked = false;
	const document = {
		client_id: clientIdUrl,
		client_name: state.clientName,
		redirect_uris: [ state.redirectUri ],
		grant_types: [ 'authorization_code', 'refresh_token' ],
		response_types: [ 'code' ],
		token_endpoint_auth_method: 'none',
	};

	const { key, cert } = ensureSelfSignedCert( CIMD_HOST );
	const fetchCount = { n: 0 };
	const { createServer } = await import( 'node:https' );
	const server = createServer( { key, cert }, ( req, res ) => {
		if ( req.url === '/dev-client/client.json' ) {
			fetchCount.n++;
			log( `Authorization server fetched the CIMD document (${ fetchCount.n }×)` );
			res.writeHead( 200, { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=300' } );
			res.end( JSON.stringify( document ) );
			return;
		}
		res.writeHead( 404 );
		res.end();
	} );

	await new Promise( ( resolvePromise, rejectPromise ) => {
		server.once( 'error', rejectPromise );
		server.listen( CIMD_PORT, '0.0.0.0', resolvePromise );
	} );

	installCimdMuPlugin( `https://${ CIMD_HOST }:${ CIMD_PORT }/` );
	state.cimd = { server, fetchCount, clientIdUrl };
	state.registration = 'cimd';
	state.clientId = clientIdUrl;
	state.authMethod = 'none';
	state.stale.client = false;
	state.stale.authorization = false;
	state.stale.tokens = false;
	log( `CIMD document being served at ${ clientIdUrl }`, document );
	log( 'Installed the mu-plugin that lets WordPress fetch it (private host + self-signed cert).' );
}

async function stopCimd() {
	if ( ! state.cimd ) {
		return;
	}
	await new Promise( ( r ) => state.cimd.server.close( r ) );
	state.cimd = null;
	removeCimdMuPlugin();
	log( 'CIMD server stopped and the mu-plugin removed.' );
}

app.get( '/authorize', async ( req, res, next ) => {
	try {
		if ( ! state.clientId ) {
			throw new Error( 'Prepare or enter a client ID before starting authorization.' );
		}
		if ( state.stale.discovery ) {
			throw new Error( 'Authorization server metadata is stale. Run discovery again first.' );
		}
		if ( state.stale.client ) {
			throw new Error( 'The prepared client is stale. Register or enable it again first.' );
		}
		const as = state.discovery || ( await discover() );
		const pkce = createPkce();
		const stateParam = randomState();

		state.pending = {
			pkce,
			state: stateParam,
			clientId: state.clientId,
			clientSecret: state.clientSecret,
			authMethod: state.authMethod,
			redirectUri: state.redirectUri,
			resource: state.resourceParam || state.resource,
		};

		const url = new URL( as.authorization_endpoint );
		url.searchParams.set( 'response_type', 'code' );
		url.searchParams.set( 'client_id', state.clientId );
		url.searchParams.set( 'redirect_uri', state.redirectUri );
		url.searchParams.set( 'scope', state.scope );
		url.searchParams.set( 'state', stateParam );
		url.searchParams.set( 'code_challenge', pkce.challenge );
		url.searchParams.set( 'code_challenge_method', 'S256' );
		url.searchParams.set( 'resource', state.resourceParam || state.resource );

		state.lastAuthorizeUrl = url.toString();
		state.stale.authorization = false;
		state.stale.tokens ||= Boolean( state.tokens );
		log( 'Opening the authorization URL in your browser — log in and approve/deny there.', state.lastAuthorizeUrl );
		res.redirect( state.lastAuthorizeUrl );
	} catch ( error ) {
		next( error );
	}
} );

app.get( '/callback', async ( req, res, next ) => {
	try {
		const params = new URLSearchParams( req.query );
		log( 'Authorization callback received.' );

		if ( ! state.pending ) {
			throw new Error( 'Callback without a pending authorization — start from "Start authorization".' );
		}

		const as = state.discovery || ( await discover() );
		const pending = state.pending;
		const client = currentClient( pending );
		let validatedParams;
		try {
			validatedParams = oauth.validateAuthResponse( as, client, params, pending.state );
		} catch ( error ) {
			if ( error instanceof oauth.AuthorizationResponseError ) {
				state.pending = null;
				log( `Authorization failed: ${ error.error }${ error.error_description ? ` — ${ error.error_description }` : '' }` );
				return res.redirect( '/' );
			}
			throw error;
		}

		log( `POST ${ as.token_endpoint } (authorization_code exchange)` );
		const response = await oauth
			.authorizationCodeGrantRequest(
				as,
				client,
				clientAuth( pending ),
				validatedParams,
				pending.redirectUri,
				pending.pkce.verifier,
				{
					...protocolRequestOptions,
					additionalParameters: new URLSearchParams( { resource: pending.resource } ),
				}
			)
			.then( ( r ) => oauth.processAuthorizationCodeResponse( as, client, r ) );

		state.tokens = response;
		state.lastRefreshToken = null;
		state.pending = null;
		state.accessTokenRevoked = false;
		state.refreshTokenRevoked = false;
		state.stale.authorization = false;
		state.stale.tokens = false;
		log( 'Token response', response );
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.post( '/token/refresh', async ( req, res, next ) => {
	try {
		if ( ! state.tokens?.refresh_token ) {
			throw new Error( 'There is no refresh token to use.' );
		}
		if ( state.stale.tokens ) {
			throw new Error( 'These tokens belong to stale configuration. Reauthorize before refreshing.' );
		}
		const as = state.discovery || ( await discover() );
		const used = state.tokens.refresh_token;
		state.lastRefreshToken = used;
		state.refreshScope = ( req.body.scope || '' ).trim();
		const additionalParameters = new URLSearchParams( { resource: state.resourceParam || state.resource } );
		if ( state.refreshScope ) {
			additionalParameters.set( 'scope', state.refreshScope );
		}

		log( `POST ${ as.token_endpoint } (refresh_token grant${ state.refreshScope ? `, requested scope: ${ state.refreshScope }` : '' })` );
		const response = await oauth
			.refreshTokenGrantRequest( as, currentClient(), clientAuth(), used, {
				...protocolRequestOptions,
				additionalParameters,
			} )
			.then( ( r ) => oauth.processRefreshTokenResponse( as, currentClient(), r ) );

		state.tokens = response;
		state.accessTokenRevoked = false;
		state.refreshTokenRevoked = false;
		log( 'Refreshed — the old refresh token is now invalid (rotation).', response );
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.post( '/token/reuse', async ( req, res, next ) => {
	try {
		const as = state.discovery || ( await discover() );
		log( `POST ${ as.token_endpoint } (replaying the previous refresh token — expect invalid_grant and family revocation)` );
		try {
			await oauth
				.refreshTokenGrantRequest( as, currentClient(), clientAuth(), state.lastRefreshToken, protocolRequestOptions )
				.then( ( r ) => oauth.processRefreshTokenResponse( as, currentClient(), r ) );
			log( 'UNEXPECTED: the replayed refresh token was accepted.' );
		} catch ( error ) {
			log( `Rejected as expected: ${ error.message }` );
		}

		if ( state.tokens?.refresh_token ) {
			log( 'Verifying the current refresh token was revoked as part of the family …' );
			try {
				await oauth
					.refreshTokenGrantRequest( as, currentClient(), clientAuth(), state.tokens.refresh_token, protocolRequestOptions )
					.then( ( r ) => oauth.processRefreshTokenResponse( as, currentClient(), r ) );
				log( 'UNEXPECTED: the current refresh token still works after reuse detection.' );
			} catch ( error ) {
				log( `Family revoked as expected: ${ error.message }` );
				state.tokens = null;
			}
		}
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.post( '/token/revoke', async ( req, res, next ) => {
	try {
		const as = state.discovery || ( await discover() );
		const tokenType = req.body.token_type === 'refresh_token' ? 'refresh_token' : 'access_token';
		const token = state.tokens?.[ tokenType ];
		if ( ! token ) {
			throw new Error( `There is no ${ tokenType.replace( '_', ' ' ) } to revoke.` );
		}
		log( `POST ${ as.revocation_endpoint } (revoking the ${ tokenType.replace( '_', ' ' ) })` );
		await oauth
			.revocationRequest( as, currentClient(), clientAuth(), token, {
				...protocolRequestOptions,
				additionalParameters: new URLSearchParams( { token_type_hint: tokenType } ),
			} )
			.then( ( r ) => oauth.processRevocationResponse( r ) );
		state.accessTokenRevoked ||= tokenType === 'access_token';
		state.refreshTokenRevoked ||= tokenType === 'refresh_token';
		log( `Revoked the ${ tokenType.replace( '_', ' ' ) }. You can now verify that it is rejected.` );
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.post( '/api', async ( req, res, next ) => {
	try {
		const method = req.body.method || 'GET';
		const path = ( req.body.path || '/wp-json/wp/v2/users/me' ).trim();
		state.apiPath = path;
		const url = `${ state.siteUrl }${ path.startsWith( '/' ) ? path : `/${ path }` }`;
		const anonymous = req.body.anonymous === '1';

		const headers = {};
		if ( ! anonymous && state.tokens?.access_token ) {
			headers.Authorization = `Bearer ${ state.tokens.access_token }`;
		}
		if ( method !== 'GET' ) {
			headers['Content-Type'] = 'application/json';
		}

		log( `${ method } ${ url }${ anonymous ? ' (no token)' : '' }` );
		if ( ! anonymous && state.stale.tokens ) {
			throw new Error( 'These tokens belong to stale configuration. Reauthorize or send the request without a token.' );
		}
		const response = await tracedRequest( 'Resource API call', method, url, {
			headers,
			body: method === 'GET' ? undefined : JSON.stringify( { title: 'dev-client probe', content: 'dev-client probe', status: 'draft' } ),
		} );

		const challenge = response.headers['www-authenticate'] || '';
		state.lastApi = { status: response.status, challenge, body: pretty( response.body ) };
		log( `HTTP ${ response.status }${ challenge ? ` · WWW-Authenticate: ${ challenge }` : '' }`, state.lastApi.body );
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.post( '/reset', async ( req, res, next ) => {
	try {
		await stopCimd();
		Object.assign( state, initialState() );
		logLines.length = 0;
		wireEntries.length = 0;
		res.redirect( '/' );
	} catch ( error ) {
		next( error );
	}
} );

app.use( ( error, req, res, _next ) => {
	log( `ERROR: ${ error.message }` );
	res.status( 500 ).type( 'html' ).send(
		`<p style="font-family:sans-serif"><strong>${ escapeHtml( error.message ) }</strong></p><p><a href="/">Back</a></p>`
	);
} );

function pretty( body ) {
	try {
		return JSON.stringify( JSON.parse( body ), null, 2 );
	} catch {
		return body.slice( 0, 2000 );
	}
}

function escapeHtml( value ) {
	return String( value ).replace( /&/g, '&amp;' ).replace( /</g, '&lt;' ).replace( />/g, '&gt;' );
}

const server = app.listen( PORT, '127.0.0.1', () => {
	log( `Dev client listening on http://127.0.0.1:${ PORT }` );
	log( `Redirect URI: http://127.0.0.1:${ PORT }/callback` );
	if ( ca ) {
		log( 'Loaded the local Caddy root CA — *.basement.localhost TLS will verify.' );
	} else {
		log( 'No local Caddy CA found — only publicly trusted TLS will verify.' );
	}
} );

async function shutdown() {
	await stopCimd();
	server.close();
}

process.once( 'SIGINT', shutdown );
process.once( 'SIGTERM', shutdown );
