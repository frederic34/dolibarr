<?php
/* Copyright (C) 2026		Frédéric France			<frederic.france@free.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * or see https://www.gnu.org/
 */

/**
 * \file    htdocs/oauthserver/lib/oauthserver.lib.php
 * \ingroup oauthserver
 * \brief   Helpers of the OAuth 2.1 authorization server: encoding, PKCE, scopes, URLs, JSON answers.
 *
 * Only native PHP is used (no OAuth library): random_bytes() for credentials,
 * hash()/hash_equals() for PKCE and for the stored hashes.
 */


/**
 * Encode binary data with the base64url alphabet, without padding (RFC 4648 section 5).
 *
 * @param	string	$data	Binary data
 * @return	string			Encoded string
 */
function oauthserverBase64UrlEncode($data)
{
	return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Generate a random credential: an optional prefix followed by base64url random bytes.
 *
 * The prefix lets the resource servers recognise an OAuth token without a query,
 * and lets secret scanners recognise a leaked one.
 *
 * @param	string	$prefix		Prefix, for example 'dolat_'
 * @param	int		$nbbytes	Number of random bytes
 * @return	string				Credential
 */
function oauthserverGenerateSecret($prefix = '', $nbbytes = 32)
{
	return $prefix.oauthserverBase64UrlEncode(random_bytes(max(1, (int) $nbbytes)));
}

/**
 * Value stored in place of a token or a code: the token itself is never stored.
 *
 * @param	string	$value	Token or code
 * @return	string			'sha256:' followed by the hex digest
 */
function oauthserverHash($value)
{
	return 'sha256:'.hash('sha256', (string) $value);
}

/**
 * Check a PKCE code_verifier against the stored S256 code_challenge (RFC 7636 section 4.6).
 *
 * @param	string	$verifier	code_verifier sent to the token endpoint
 * @param	string	$challenge	code_challenge stored with the authorization code
 * @return	bool				True if the verifier matches
 */
function oauthserverCheckPkce($verifier, $challenge)
{
	// RFC 7636 section 4.1: 43 to 128 characters among [A-Z] [a-z] [0-9] - . _ ~
	// The D modifier makes $ match only at the very end (no trailing newline).
	if (!is_string($challenge) || $challenge === '' || !preg_match('/^[A-Za-z0-9\-._~]{43,128}$/D', (string) $verifier)) {
		return false;
	}

	return hash_equals($challenge, oauthserverBase64UrlEncode(hash('sha256', $verifier, true)));
}

/**
 * Issuer identifier of the authorization server (RFC 8414).
 *
 * @param	string	$mainurlroot	Root URL of Dolibarr, DOL_MAIN_URL_ROOT when empty
 * @return	string					Issuer URL
 */
function oauthserverGetIssuer($mainurlroot = '')
{
	return ($mainurlroot !== '' ? $mainurlroot : DOL_MAIN_URL_ROOT).'/oauthserver';
}

/**
 * URL of a protected resource, as used in the resource parameter (RFC 8707).
 *
 * @param	string	$audience		'mcp' or 'api'
 * @param	string	$mainurlroot	Root URL of Dolibarr, DOL_MAIN_URL_ROOT when empty
 * @return	string					Resource URL
 */
function oauthserverGetResourceUrl($audience, $mainurlroot = '')
{
	$root = ($mainurlroot !== '' ? $mainurlroot : DOL_MAIN_URL_ROOT);
	if ($audience === 'mcp') {
		return $root.'/ai/server/mcp_server.php';
	}

	return $root.'/api/index.php';
}

/**
 * URL where RFC 8414 clients look for the metadata: the well-known segment is
 * inserted between the host and the path of the issuer.
 *
 * @param	string	$mainurlroot	Root URL of Dolibarr, DOL_MAIN_URL_ROOT when empty
 * @return	string					Well-known URL, or '' if the issuer cannot be parsed
 */
function oauthserverGetWellKnownUrl($mainurlroot = '')
{
	$parts = parse_url(oauthserverGetIssuer($mainurlroot));
	if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
		return '';
	}
	$origin = $parts['scheme'].'://'.$parts['host'].(empty($parts['port']) ? '' : ':'.$parts['port']);

	return $origin.'/.well-known/oauth-authorization-server'.(empty($parts['path']) ? '' : $parts['path']);
}

/**
 * Scopes known by the server.
 *
 * @return	string[]	Scopes
 */
function oauthserverGetSupportedScopes()
{
	return ['api', 'mcp', 'read', 'write', 'offline_access'];
}

/**
 * Split a space separated scope string.
 *
 * @param	string		$scope	Scope string
 * @return	string[]			Distinct scopes, in their order of appearance
 */
function oauthserverParseScopes($scope)
{
	$list = preg_split('/\s+/', trim((string) $scope), -1, PREG_SPLIT_NO_EMPTY);

	return is_array($list) ? array_values(array_unique($list)) : [];
}

/**
 * Compute the scopes to grant (spec section 4).
 *
 * @param	string		$requested		Value of the scope parameter, may be empty
 * @param	string[]	$allowed		Scopes allowed to the client
 * @param	string		$resource		Value of the resource parameter (RFC 8707), may be empty
 * @param	string		$error			Set to an OAuth error code when null is returned
 * @param	string		$mainurlroot	Root URL of Dolibarr, DOL_MAIN_URL_ROOT when empty
 * @return	string[]|null				Granted scopes, sorted, or null on error
 */
function oauthserverResolveScopes($requested, $allowed, $resource, &$error, $mainurlroot = '')
{
	$error = '';
	$scopes = oauthserverParseScopes($requested);
	if (empty($scopes)) {
		$scopes = $allowed;
	}
	foreach ($scopes as $scope) {
		if (!in_array($scope, oauthserverGetSupportedScopes(), true) || !in_array($scope, $allowed, true)) {
			$error = 'invalid_scope';
			return null;
		}
	}

	if ($resource !== '') {
		if ($resource === oauthserverGetResourceUrl('mcp', $mainurlroot)) {
			$keep = 'mcp';
			$drop = 'api';
		} elseif ($resource === oauthserverGetResourceUrl('api', $mainurlroot)) {
			$keep = 'api';
			$drop = 'mcp';
		} else {
			$error = 'invalid_target';
			return null;
		}
		if (!in_array($keep, $allowed, true)) {
			$error = 'invalid_scope';
			return null;
		}
		$scopes = array_values(array_diff($scopes, [$drop]));
		if (!in_array($keep, $scopes, true)) {
			$scopes[] = $keep;
		}
	}

	if (!in_array('api', $scopes, true) && !in_array('mcp', $scopes, true)) {
		$error = 'invalid_scope';
		return null;
	}
	sort($scopes);

	return $scopes;
}

/**
 * Check a redirect URI before it is registered: https, or http on a loopback
 * host for native applications (RFC 8252 section 7.3), never a fragment.
 *
 * @param	string	$uri	Redirect URI
 * @return	bool			True if acceptable
 */
function oauthserverIsValidRedirectUri($uri)
{
	if (!is_string($uri) || $uri === '' || strlen($uri) > 2000) {
		return false;
	}
	$parts = parse_url($uri);
	if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host']) || isset($parts['fragment'])) {
		return false;
	}
	$scheme = strtolower($parts['scheme']);
	if ($scheme === 'https') {
		return true;
	}
	if ($scheme === 'http') {
		return in_array(strtolower($parts['host']), ['127.0.0.1', 'localhost', '[::1]'], true);
	}

	return false;
}

/**
 * Add parameters to a redirect URI that may already have a query string.
 * Empty values (for example an absent state) are left out.
 *
 * @param	string					$redirecturi	Registered redirect URI
 * @param	array<string,string>	$params			Parameters to add
 * @return	string									URL to redirect to
 */
function oauthserverBuildRedirectUrl($redirecturi, $params)
{
	$params = array_filter($params, function ($value) {
		return $value !== '';
	});

	return $redirecturi.(strpos($redirecturi, '?') === false ? '?' : '&').http_build_query($params, '', '&', PHP_QUERY_RFC3986);
}

/**
 * Whether the request came over HTTPS. OAUTHSERVER_ALLOW_HTTP lifts the check
 * on development instances.
 *
 * @param	array<string,mixed>|null	$server		Server variables, defaults to $_SERVER
 * @return	bool								True if HTTPS (or allowed without)
 */
function oauthserverIsSecureRequest($server = null)
{
	if ($server === null) {
		$server = $_SERVER;
	}
	if (getDolGlobalString('OAUTHSERVER_ALLOW_HTTP')) {
		return true;
	}
	if (!empty($server['HTTPS']) && strtolower((string) $server['HTTPS']) !== 'off') {
		return true;
	}
	if (!empty($server['SERVER_PORT']) && (string) $server['SERVER_PORT'] === '443') {
		return true;
	}

	return (!empty($server['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $server['HTTP_X_FORWARDED_PROTO']) === 'https');
}

/**
 * Read the client credentials of a token or revocation request (RFC 6749 section 2.3.1).
 *
 * A client must use one method only: the Basic header with a different
 * client_id or with a client_secret in the body is refused ('conflict').
 *
 * @param	array<string,mixed>|null	$server		Server variables, defaults to $_SERVER (then the request headers are read too)
 * @return	array{client_id:string,client_secret:string,method:string}	method is 'basic', 'post', 'none' or 'conflict'
 */
function oauthserverGetClientCredentials($server = null)
{
	$readheaders = ($server === null);
	if ($server === null) {
		$server = $_SERVER;
	}
	$conflict = ['client_id' => '', 'client_secret' => '', 'method' => 'conflict'];

	// Body parameters only (method 2 = POST), RFC 6749 section 2.3.1. A query string value is never read.
	$bodyid = GETPOST('client_id', 'alphanohtml', 2);
	$bodysecret = GETPOST('client_secret', 'alphanohtml', 2);
	// A value present but malformed is refused, not silently dropped.
	$charset = '/^[A-Za-z0-9_.\-~]+$/D';
	if (($bodyid !== '' && !preg_match($charset, $bodyid)) || ($bodysecret !== '' && !preg_match($charset, $bodysecret))) {
		return $conflict;
	}

	$header = '';
	if (!empty($server['HTTP_AUTHORIZATION'])) {
		$header = (string) $server['HTTP_AUTHORIZATION'];
	} elseif (!empty($server['REDIRECT_HTTP_AUTHORIZATION'])) {
		$header = (string) $server['REDIRECT_HTTP_AUTHORIZATION'];
	} elseif ($readheaders && function_exists('getallheaders')) {
		// Apache in CGI/FastCGI mode hides the header from $_SERVER unless CGIPassAuth is on
		$allheaders = array_change_key_case((array) getallheaders(), CASE_LOWER);
		$header = (isset($allheaders['authorization']) ? (string) $allheaders['authorization'] : '');
	}

	$reg = [];
	if (preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/iD', $header, $reg)) {
		$decoded = base64_decode($reg[1], true);
		if ($decoded === false || strpos($decoded, ':') === false || $bodysecret !== '') {
			return $conflict;
		}
		list($id, $secret) = explode(':', $decoded, 2);
		$id = urldecode($id);
		if ($bodyid !== '' && $bodyid !== $id) {
			return $conflict;
		}

		return ['client_id' => $id, 'client_secret' => urldecode($secret), 'method' => 'basic'];
	}

	if ($bodysecret !== '') {
		return ['client_id' => $bodyid, 'client_secret' => $bodysecret, 'method' => 'post'];
	}

	return ['client_id' => $bodyid, 'client_secret' => '', 'method' => 'none'];
}

/**
 * Send a JSON answer of the authorization server. Tokens must never be cached.
 *
 * @param	int						$httpcode	HTTP status
 * @param	array<string,mixed>		$data		Body
 * @param	string[]				$headers	Extra header lines
 * @return	void
 */
function oauthserverSendJson($httpcode, $data, $headers = [])
{
	http_response_code($httpcode);
	header('Content-Type: application/json; charset=utf-8');
	header('Cache-Control: no-store');
	header('Pragma: no-cache');
	header('X-Content-Type-Options: nosniff');
	foreach ($headers as $header) {
		header($header);
	}
	print json_encode($data, JSON_UNESCAPED_SLASHES);
}

/**
 * Send an OAuth error answer (RFC 6749 section 5.2).
 *
 * @param	int			$httpcode		HTTP status
 * @param	string		$error			OAuth error code
 * @param	string		$description	Human readable description
 * @param	string[]	$headers		Extra header lines
 * @return	void
 */
function oauthserverSendError($httpcode, $error, $description = '', $headers = [])
{
	$data = ['error' => $error];
	if ($description !== '') {
		$data['error_description'] = $description;
	}
	oauthserverSendJson($httpcode, $data, $headers);
}
