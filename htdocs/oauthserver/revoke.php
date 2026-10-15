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
 * \file    htdocs/oauthserver/revoke.php
 * \ingroup oauthserver
 * \brief   Revocation endpoint (RFC 7009): a client revokes one of its access or refresh tokens
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

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthservertoken.class.php';

/**
 * @var DoliDB $db
 * @var User $user
 */

if (!isModEnabled('oauthserver')) {
	oauthserverSendError(404, 'invalid_request', 'The OAuth server is disabled');
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

$credentials = oauthserverGetClientCredentials();
$client = new OAuthServerClient($db);
if ($client->authenticate($credentials) <= 0) {
	sleep(1);
	oauthserverSendError(401, 'invalid_client', 'Client authentication failed', ($credentials['method'] === 'basic' ? ['WWW-Authenticate: Basic realm="Dolibarr OAuth"'] : []));
	exit;
}

// Parameters come from the POST body only (RFC 7009 section 2.1), raw, without default.
// token_type_hint is optional and ignored: the token prefix tells the type.
$token = GETPOST('token', 'aZ09', 2, null, null, 1, 1);
$grant = new OAuthServerToken($db);
$found = (strpos($token, OAuthServerToken::REFRESH_PREFIX) === 0 ? $grant->fetchByRefreshToken($token) : $grant->fetchByAccessToken($token));
// RFC 7009 section 2.2: an unknown token, or a token of another client, gets the same answer.
if ($found === 1 && $grant->fk_oauth_client === (int) $client->id) {
	$grant->revoke($user);
}

oauthserverSendJson(200, []);
