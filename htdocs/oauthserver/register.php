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
 * \file    htdocs/oauthserver/register.php
 * \ingroup oauthserver
 * \brief   Dynamic Client Registration (RFC 7591), for MCP clients. Off unless OAUTHSERVER_ALLOW_DCR is set.
 *          Only public clients (PKCE, no secret) can register here.
 */

if (!defined('NOLOGIN')) {
	define('NOLOGIN', '1');
}
if (!defined('NOCSRFCHECK')) {
	define('NOCSRFCHECK', '1');
}
if (!defined('NOTOKENRENEWAL')) {
	define('NOTOKENRENEWAL', '1');
}
if (!defined('NOREQUIREMENU')) {
	define('NOREQUIREMENU', '1');
}
if (!defined('NOREQUIREHTML')) {
	define('NOREQUIREHTML', '1');
}
if (!defined('NOREQUIREAJAX')) {
	define('NOREQUIREAJAX', '1');
}
if (!defined('NOSESSION')) {
	define('NOSESSION', '1');
}

// Use the configuration of the entity asked by the HTTP header, like the REST API does
if (!empty($_SERVER['HTTP_DOLAPIENTITY']) && (int) $_SERVER['HTTP_DOLAPIENTITY'] > 0) {
	define('DOLENTITY', (int) $_SERVER['HTTP_DOLAPIENTITY']);
}

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';

/**
 * Whether a JSON value is a list of strings.
 *
 * @param	mixed	$value	Decoded JSON value
 * @return	bool			True for a list of strings (possibly empty)
 */
function oauthserverIsStringList($value)
{
	if (!is_array($value) || array_values($value) !== $value) {
		return false;
	}
	foreach ($value as $item) {
		if (!is_string($item)) {
			return false;
		}
	}

	return true;
}

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var User $user
 */

// Without the module multicompany, entity 1 is the only one
if ((int) $conf->entity !== 1 && !isModEnabled('multicompany')) {
	oauthserverSendError(400, 'invalid_client_metadata', 'Unknown entity');
	exit;
}

if (!isModEnabled('oauthserver') || !getDolGlobalString('OAUTHSERVER_ALLOW_DCR')) {
	http_response_code(404);
	exit;
}
if (!oauthserverIsSecureRequest()) {
	oauthserverSendError(400, 'invalid_request', 'HTTPS is required');
	exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	oauthserverSendError(405, 'invalid_request', 'Use POST', ['Allow: POST']);
	exit;
}

$raw = (string) file_get_contents('php://input', false, null, 0, 16385);
$meta = (strlen($raw) > 16384 ? null : json_decode($raw, true));
if (!is_array($meta)) {
	oauthserverSendError(400, 'invalid_client_metadata', 'The body must be a JSON object of at most 16 KB');
	exit;
}

// Hourly cap on registrations: the endpoint is open to anybody
$sql = "SELECT COUNT(rowid) as nb FROM ".$db->prefix()."oauth_client";
$sql .= " WHERE registration_type = 'dynamic' AND datec > '".$db->idate(dol_now() - 3600)."'";
$resql = $db->query($sql);
$obj = ($resql ? $db->fetch_object($resql) : null);
if (!$obj || (int) $obj->nb >= getDolGlobalInt('OAUTHSERVER_DCR_MAX_PER_HOUR', 20)) {
	oauthserverSendError(429, 'temporarily_unavailable', 'Too many registrations, try again later', ['Retry-After: 3600']);
	exit;
}

// A field that is present must have its exact type (RFC 7591 section 2): never fall back to a default
foreach (['client_name', 'scope', 'token_endpoint_auth_method'] as $field) {
	if (array_key_exists($field, $meta) && !is_string($meta[$field])) {
		oauthserverSendError(400, 'invalid_client_metadata', $field.' must be a string');
		exit;
	}
}
foreach (['redirect_uris', 'grant_types', 'response_types'] as $field) {
	if (array_key_exists($field, $meta) && !oauthserverIsStringList($meta[$field])) {
		oauthserverSendError(400, 'invalid_client_metadata', $field.' must be an array of strings');
		exit;
	}
}

// redirect_uris: required, 1 to 10 valid URIs
$uris = (isset($meta['redirect_uris']) ? $meta['redirect_uris'] : []);
if (empty($uris) || count($uris) > 10) {
	oauthserverSendError(400, 'invalid_redirect_uri', 'redirect_uris must list 1 to 10 URIs');
	exit;
}
foreach ($uris as $uri) {
	if (!oauthserverIsValidRedirectUri($uri)) {
		oauthserverSendError(400, 'invalid_redirect_uri', 'Redirect URIs must be https://, or http:// on a loopback address, in ASCII, without fragment');
		exit;
	}
}

$method = (isset($meta['token_endpoint_auth_method']) ? $meta['token_endpoint_auth_method'] : 'none');
$granttypes = (isset($meta['grant_types']) ? $meta['grant_types'] : ['authorization_code']);
$responsetypes = (isset($meta['response_types']) ? $meta['response_types'] : ['code']);
$dcrscopes = oauthserverParseScopes(getDolGlobalString('OAUTHSERVER_DCR_SCOPES', 'mcp read write offline_access'));
$scopes = (isset($meta['scope']) ? oauthserverParseScopes($meta['scope']) : $dcrscopes);
if ($method !== 'none'
	|| array_diff($granttypes, ['authorization_code', 'refresh_token']) || array_diff($responsetypes, ['code'])
	|| empty($scopes) || array_diff($scopes, $dcrscopes)) {
	oauthserverSendError(400, 'invalid_client_metadata', 'Only public clients (token_endpoint_auth_method none) with the authorization_code and refresh_token grants and the scopes '.implode(' ', $dcrscopes).' can register');
	exit;
}

$name = (isset($meta['client_name']) ? trim(dol_string_nohtmltag($meta['client_name'])) : '');
$name = dol_trunc(($name !== '' ? $name : 'Unnamed application'), 250, 'right', 'UTF-8', 1);

$client = new OAuthServerClient($db);
$client->entity = (int) $conf->entity;
$client->label = $name;
$client->redirect_uris = $uris;
$client->allowed_scopes = $scopes;
$client->token_endpoint_auth_method = 'none';
$client->registration_type = 'dynamic';
if ($client->create($user) <= 0) {
	oauthserverSendError(400, 'invalid_client_metadata', 'The client could not be registered');
	exit;
}

oauthserverSendJson(201, [
	'client_id' => $client->client_id,
	'client_id_issued_at' => (int) $client->datec,
	'client_name' => $client->label,
	'redirect_uris' => $client->redirect_uris,
	'grant_types' => array_values($granttypes),
	'response_types' => ['code'],
	'token_endpoint_auth_method' => 'none',
	'scope' => implode(' ', $client->allowed_scopes),
]);
