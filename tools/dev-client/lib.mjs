/**
 * Shared primitives for the dev client: HTTP with the local Caddy CA,
 * PKCE, and small Docker helpers. Zero dependencies.
 */

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { dirname, join, resolve } from 'node:path';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';

const TOOL_DIR = dirname( fileURLToPath( import.meta.url ) );
export const REPO_ROOT = resolve( TOOL_DIR, '..', '..', '..', '..', '..' );
export const CACHE_DIR = join( TOOL_DIR, '.cache' );

export function sh( command, args, { allowFailure = false } = {} ) {
	const result = spawnSync( command, args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 } );

	if ( result.error ) {
		throw new Error( `Failed to run ${ command }: ${ result.error.message }` );
	}

	if ( result.status !== 0 && ! allowFailure ) {
		throw new Error( `${ command } ${ args.join( ' ' ) } exited ${ result.status }: ${ result.stderr || result.stdout }` );
	}

	return result;
}

const containerIds = new Map();

export function containerId( service ) {
	if ( ! containerIds.has( service ) ) {
		const { stdout } = sh( 'docker', [
			'compose',
			'-f',
			join( REPO_ROOT, 'docker-compose.yml' ),
			'ps',
			'-q',
			service,
		] );
		const id = stdout.trim();
		if ( ! id ) {
			throw new Error( `No running container for compose service "${ service }" — is the dev environment up (npm start)?` );
		}
		containerIds.set( service, id );
	}
	return containerIds.get( service );
}

/** Export Caddy's internal root CA so Node trusts the dev site's certificate. Returns null when there is no local Caddy. */
export function loadCaddyCa() {
	try {
		mkdirSync( CACHE_DIR, { recursive: true } );
		const target = join( CACHE_DIR, 'caddy-root-ca.crt' );
		const copy = sh(
			'docker',
			[ 'cp', `${ containerId( 'caddy-proxy' ) }:/data/caddy/pki/authorities/local/root.crt`, target ],
			{ allowFailure: true }
		);
		if ( copy.status === 0 && existsSync( target ) ) {
			return readFileSync( target );
		}
	} catch {
		// Docker is optional when the target site has a publicly trusted certificate.
	}

	return null;
}

export class HttpClient {
	constructor( ca ) {
		this.ca = ca ? [ ...rootCertificates, ca ] : undefined;
	}

	/** One request, never following redirects. Retries once on 502 (the dev proxy blips when upstreams change). */
	async request( method, url, { headers = {}, body } = {} ) {
		let response = await this.#once( method, url, { headers, body } );
		if ( response.status === 502 ) {
			await new Promise( ( r ) => setTimeout( r, 700 ) );
			response = await this.#once( method, url, { headers, body } );
		}
		return response;
	}

	#once( method, url, { headers, body } ) {
		return new Promise( ( resolvePromise, rejectPromise ) => {
			const target = new URL( url );
			const transport = target.protocol === 'https:' ? https : http;
			const outgoing = Object.fromEntries( new Headers( headers ).entries() );

			let payload;
			if ( body !== undefined ) {
				payload = typeof body === 'string' ? body : new URLSearchParams( body ).toString();
				outgoing['Content-Length'] = Buffer.byteLength( payload );
				if ( ! Object.keys( outgoing ).some( ( k ) => k.toLowerCase() === 'content-type' ) ) {
					outgoing['Content-Type'] = 'application/x-www-form-urlencoded';
				}
			}

			const requestOptions = {
				method,
				hostname: target.hostname,
				port: target.port || ( target.protocol === 'https:' ? 443 : 80 ),
				path: `${ target.pathname }${ target.search }`,
				headers: outgoing,
				timeout: 15000,
			};
			if ( this.ca ) {
				requestOptions.ca = this.ca;
			}

			const req = transport.request(
				requestOptions,
				( res ) => {
					const chunks = [];
					res.on( 'data', ( chunk ) => chunks.push( chunk ) );
					res.on( 'end', () =>
						resolvePromise( {
							status: res.statusCode,
							headers: res.headers,
							body: Buffer.concat( chunks ).toString( 'utf8' ),
						} )
					);
				}
			);

			req.on( 'timeout', () => req.destroy( new Error( `Request timed out: ${ method } ${ url }` ) ) );
			req.on( 'error', rejectPromise );
			if ( payload !== undefined ) {
				req.write( payload );
			}
			req.end();
		} );
	}

	async fetch( url, options = {} ) {
		const response = await this.request( options.method || 'GET', url, {
			headers: options.headers,
			body: options.body,
		} );

		return new Response( [ 101, 204, 205, 304 ].includes( response.status ) ? null : response.body, {
			status: response.status,
			headers: response.headers,
		} );
	}

}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636, S256)
// ---------------------------------------------------------------------------

export function createPkce() {
	const verifier = randomBytes( 32 ).toString( 'base64url' );
	const challenge = createHash( 'sha256' ).update( verifier ).digest( 'base64url' );
	return { verifier, challenge };
}

export function randomState() {
	return randomBytes( 12 ).toString( 'base64url' );
}

// ---------------------------------------------------------------------------
// Discovery and inspector helpers
// ---------------------------------------------------------------------------

const SECRET_FIELD = /^(?:authorization|client_secret|access_token|refresh_token|code|code_verifier)$/i;

function redactedValue( value ) {
	if ( typeof value !== 'string' ) {
		return '[redacted]';
	}
	return value.length > 12 ? `${ value.slice( 0, 8 ) }… (${ value.length } chars)` : '[redacted]';
}

export function redactSecrets( value, key = '' ) {
	if ( SECRET_FIELD.test( key ) ) {
		return redactedValue( value );
	}
	if ( Array.isArray( value ) ) {
		return value.map( ( item ) => redactSecrets( item ) );
	}
	if ( value && typeof value === 'object' ) {
		return Object.fromEntries( Object.entries( value ).map( ( [ childKey, childValue ] ) => [ childKey, redactSecrets( childValue, childKey ) ] ) );
	}
	return value;
}

export function redactUrl( value ) {
	try {
		const url = new URL( value );
		for ( const key of url.searchParams.keys() ) {
			if ( SECRET_FIELD.test( key ) ) {
				url.searchParams.set( key, redactedValue( url.searchParams.get( key ) ) );
			}
		}
		return url.toString();
	} catch {
		return value;
	}
}

function redactBody( body, headers = {} ) {
	if ( typeof body !== 'string' || body === '' ) {
		return body;
	}
	const contentType = Object.entries( headers ).find( ( [ key ] ) => key.toLowerCase() === 'content-type' )?.[1] || '';
	try {
		if ( String( contentType ).includes( 'json' ) || /^[\s]*[\[{]/.test( body ) ) {
			return JSON.stringify( redactSecrets( JSON.parse( body ) ), null, 2 );
		}
		if ( String( contentType ).includes( 'application/x-www-form-urlencoded' ) || /^[^=&]+=[^&]*/.test( body ) ) {
			const params = new URLSearchParams( body );
			for ( const key of params.keys() ) {
				if ( SECRET_FIELD.test( key ) ) {
					params.set( key, redactedValue( params.get( key ) ) );
				}
			}
			return params.toString();
		}
	} catch {
		// Keep malformed fixture bodies visible in the inspector.
	}
	return body.length > 6000 ? `${ body.slice( 0, 6000 ) }\n… truncated` : body;
}

export function redactHttpTrace( trace ) {
	const copy = structuredClone( trace );
	copy.request.url = redactUrl( copy.request.url );
	copy.request.headers = redactSecrets( copy.request.headers );
	copy.request.body = redactBody( copy.request.body, copy.request.headers );
	if ( copy.response ) {
		copy.response.headers = redactSecrets( copy.response.headers );
		copy.response.body = redactBody( copy.response.body, copy.response.headers );
	}
	return copy;
}

export function extractResourceMetadataUrl( challenge ) {
	const match = String( challenge || '' ).match( /(?:^|[,\s])resource_metadata\s*=\s*"((?:[^"\\]|\\.)*)"/i );
	return match ? match[1].replace( /\\(["\\])/g, '$1' ) : null;
}

// ---------------------------------------------------------------------------
// CIMD support: a self-signed HTTPS cert for host.docker.internal and the
// mu-plugin that lets WordPress fetch it (documented dev escape hatches).
// ---------------------------------------------------------------------------

export function ensureSelfSignedCert( host ) {
	mkdirSync( CACHE_DIR, { recursive: true } );
	const keyPath = join( CACHE_DIR, 'cimd-key.pem' );
	const certPath = join( CACHE_DIR, 'cimd-cert.pem' );

	if ( ! existsSync( keyPath ) || ! existsSync( certPath ) ) {
		const attempt = sh( 'openssl', [
			'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
			'-keyout', keyPath, '-out', certPath, '-days', '7',
			'-subj', `/CN=${ host }`,
			'-addext', `subjectAltName=DNS:${ host }`,
		], { allowFailure: true } );
		if ( attempt.status !== 0 ) {
			sh( 'openssl', [
				'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
				'-keyout', keyPath, '-out', certPath, '-days', '7',
				'-subj', `/CN=${ host }`,
			] );
		}
	}

	return { key: readFileSync( keyPath ), cert: readFileSync( certPath ) };
}

const MU_PLUGIN_NAME = 'oauth-pilot-dev-client-cimd.php';

/**
 * Let the WordPress container fetch the metadata document this tool serves on
 * the host: skip the SSRF guard for the fixture URL (host.docker.internal is a
 * private address) and TLS verification for its self-signed certificate.
 * tools/local is gitignored, so nothing persists in the repo.
 */
export function installCimdMuPlugin( urlPrefix ) {
	const muDir = join( REPO_ROOT, 'tools', 'local', 'wp-content', 'mu-plugins' );
	if ( ! existsSync( muDir ) ) {
		throw new Error( `${ muDir } does not exist — is this the local Docker WordPress?` );
	}
	const escapedUrlPrefix = urlPrefix.replace( /\\/g, '\\\\' ).replace( /'/g, "\\'" );
	writeFileSync(
		join( muDir, MU_PLUGIN_NAME ),
		`<?php
// Installed by packages/plugins/oauth-pilot/tools/dev-client for manual CIMD testing.
// Local development only. Delete this file or press "Disable CIMD" in the tool to remove.
add_filter( 'oauth_pilot__cimd_url_allowed', function ( $allowed, $url ) {
	return 0 === strpos( (string) $url, '${ escapedUrlPrefix }' ) ? true : $allowed;
}, 10, 2 );

add_filter( 'http_request_args', function ( $args, $url ) {
	if ( 0 === strpos( (string) $url, '${ escapedUrlPrefix }' ) ) {
		$args['sslverify'] = false;
	}
	return $args;
}, 10, 2 );
`
	);
}

export function removeCimdMuPlugin() {
	const target = join( REPO_ROOT, 'tools', 'local', 'wp-content', 'mu-plugins', MU_PLUGIN_NAME );
	if ( existsSync( target ) ) {
		rmSync( target );
	}
}
