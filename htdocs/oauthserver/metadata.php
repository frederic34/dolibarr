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
 * \file    htdocs/oauthserver/metadata.php
 * \ingroup oauthserver
 * \brief   Authorization server metadata (RFC 8414). Served at the well-known URL by a web server rewrite rule.
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

// Load Dolibarr environment
require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';

if (!isModEnabled('oauthserver')) {
	http_response_code(404);
	exit;
}

if (!oauthserverIsSecureRequest()) {
	oauthserverSendError(400, 'invalid_request', 'HTTPS is required');
	exit;
}

$issuer = oauthserverGetIssuer();
$authmethods = ['none', 'client_secret_basic', 'client_secret_post'];

$metadata = [
	'issuer' => $issuer,
	'authorization_endpoint' => $issuer.'/authorize.php',
	'token_endpoint' => $issuer.'/token.php',
	'revocation_endpoint' => $issuer.'/revoke.php',
	'response_types_supported' => ['code'],
	'grant_types_supported' => ['authorization_code', 'refresh_token'],
	'code_challenge_methods_supported' => ['S256'],
	'token_endpoint_auth_methods_supported' => $authmethods,
	'revocation_endpoint_auth_methods_supported' => $authmethods,
	'scopes_supported' => oauthserverGetSupportedScopes(),
	'authorization_response_iss_parameter_supported' => true,
];

// Public document: browser based clients (MCP Inspector...) may read it.
oauthserverSendJson(200, $metadata, ['Access-Control-Allow-Origin: *']);
exit;
