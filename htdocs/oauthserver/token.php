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
 * \file    htdocs/oauthserver/token.php
 * \ingroup oauthserver
 * \brief   Token endpoint: authorization_code (with PKCE) and refresh_token grants
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
require_once DOL_DOCUMENT_ROOT.'/user/class/user.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverauthcode.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthservertoken.class.php';

/**
 * Answer with the tokens of a grant just issued or rotated.
 *
 * @param	OAuthServerToken	$grant	Grant
 * @return	void
 */
function oauthserverSendTokens($grant)
{
	$data = [
		'access_token' => $grant->access_token,
		'token_type' => 'Bearer',
		'expires_in' => OAuthServerToken::getAccessLifetime(),
		'scope' => implode(' ', $grant->scopes),
	];
	if ($grant->refresh_token !== '') {
		$data['refresh_token'] = $grant->refresh_token;
	}
	oauthserverSendJson(200, $data);
}

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
	sleep(1);	// Anti brute force protection, same delay as the REST API on a bad key
	oauthserverSendError(401, 'invalid_client', 'Client authentication failed', ($credentials['method'] === 'basic' ? ['WWW-Authenticate: Basic realm="Dolibarr OAuth"'] : []));
	exit;
}

// Protocol parameters come from the POST body only (RFC 6749 section 3.2), raw, without default
$granttype = GETPOST('grant_type', 'aZ09', 2, null, null, 1, 1);

if ($granttype === 'authorization_code') {
	$authcode = new OAuthServerAuthCode($db);
	if ($authcode->fetchByCode(GETPOST('code', 'aZ09', 2, null, null, 1, 1)) <= 0 || $authcode->fk_oauth_client !== (int) $client->id) {
		oauthserverSendError(400, 'invalid_grant', 'Unknown authorization code');
		exit;
	}
	if ($authcode->date_used !== null) {
		// The code came back: it may have been intercepted. Revoke what it produced (RFC 6749 section 4.1.2).
		$grant = new OAuthServerToken($db);
		if ($authcode->fk_oauth_token > 0 && $grant->fetch($authcode->fk_oauth_token) > 0) {
			$grant->revoke($user, 'OAUTHSERVER_CODE_REPLAY');
		}
		oauthserverSendError(400, 'invalid_grant', 'The authorization code was already used');
		exit;
	}
	if ($authcode->isExpired() || GETPOST('redirect_uri', 'alphanohtml', 2, null, null, 1, 1) !== $authcode->redirect_uri
		|| !oauthserverCheckPkce(GETPOST('code_verifier', 'alphanohtml', 2, null, null, 1, 1), $authcode->code_challenge)) {
		oauthserverSendError(400, 'invalid_grant', 'The authorization code is expired or does not match this request');
		exit;
	}
	// Same rule as OAuthServerToken::isUserAllowed(), with the date of the code
	$tokenuser = new User($db);
	if ($tokenuser->fetch($authcode->fk_user) <= 0 || (int) $tokenuser->status !== User::STATUS_ENABLED || $tokenuser->isNotIntoValidityDateRange()
		|| (!empty($tokenuser->flagdelsessionsbefore) && $authcode->datec < (int) $tokenuser->flagdelsessionsbefore)) {
		oauthserverSendError(400, 'invalid_grant', 'The user of this authorization is not allowed any more');
		exit;
	}

	$db->begin();
	$grant = new OAuthServerToken($db);
	if ($grant->issue($tokenuser, (int) $client->id, $authcode->fk_user, $authcode->scopes, $authcode->entity) < 0 || $authcode->markUsed($grant->id) !== 1) {
		$db->rollback();
		oauthserverSendError(400, 'invalid_grant', 'The authorization code could not be redeemed');
		exit;
	}
	$client->markUsed();
	$db->commit();

	oauthserverSendTokens($grant);
	exit;
}

if ($granttype === 'refresh_token') {
	$grant = new OAuthServerToken($db);
	$found = $grant->fetchByRefreshToken(GETPOST('refresh_token', 'aZ09', 2, null, null, 1, 1));
	if ($found === 2 && !$grant->isInRefreshGrace()) {
		// A replaced refresh token came back after the grace period: it was copied. Revoke the grant.
		$grant->revoke($user, 'OAUTHSERVER_REFRESH_REUSE');
	}
	if ($found !== 1 || $grant->fk_oauth_client !== (int) $client->id) {
		oauthserverSendError(400, 'invalid_grant', 'Unknown or replaced refresh token');
		exit;
	}
	if ($grant->expire_refresh_at === null || $grant->expire_refresh_at <= dol_now()) {
		oauthserverSendError(400, 'invalid_grant', 'The refresh token expired');
		exit;
	}
	$tokenuser = new User($db);
	if ($tokenuser->fetch($grant->fk_user) <= 0 || !$grant->isUserAllowed($tokenuser)) {
		oauthserverSendError(400, 'invalid_grant', 'The user of this authorization is not allowed any more');
		exit;
	}

	// A refresh may narrow the scopes, never widen them
	$requested = oauthserverParseScopes(GETPOST('scope', 'alphanohtml', 2, null, null, 1, 1));
	if (!empty($requested) && array_diff($requested, $grant->scopes)) {
		oauthserverSendError(400, 'invalid_scope', 'A refresh cannot add scopes');
		exit;
	}
	$newscopes = (empty($requested) ? $grant->scopes : $requested);
	if (!in_array('offline_access', $newscopes, true)) {
		$newscopes[] = 'offline_access';
	}
	// The scopes allowed to the client may have been narrowed since the grant was given
	if (!in_array('offline_access', $client->allowed_scopes, true)) {
		oauthserverSendError(400, 'invalid_grant', 'The client is not allowed offline access any more');
		exit;
	}
	$newscopes = array_values(array_intersect($newscopes, $client->allowed_scopes));
	if (!in_array('api', $newscopes, true) && !in_array('mcp', $newscopes, true)) {
		oauthserverSendError(400, 'invalid_scope', 'The scopes must keep api or mcp');
		exit;
	}
	sort($newscopes);

	if ($grant->rotate($newscopes) !== 1) {
		oauthserverSendError(400, 'invalid_grant', 'The refresh token was already used');
		exit;
	}
	$client->markUsed();

	oauthserverSendTokens($grant);
	exit;
}

oauthserverSendError(400, 'unsupported_grant_type', 'Supported grant types: authorization_code, refresh_token');
