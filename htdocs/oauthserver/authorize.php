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
 * \file    htdocs/oauthserver/authorize.php
 * \ingroup oauthserver
 * \brief   Authorization endpoint: the logged user grants an application access to Dolibarr (OAuth 2.1 with PKCE)
 */

// The "allow" POST creates a credential: its CSRF token is checked even when the instance disables the CSRF check
if (!defined('CSRFCHECK_WITH_TOKEN')) {
	define('CSRFCHECK_WITH_TOKEN', '1');
}
// The consent screen must never be framed (clickjacking)
if (!defined('MAIN_SECURITY_FORCECSP')) {
	define('MAIN_SECURITY_FORCECSP', "frame-ancestors 'none'");
}

// Load Dolibarr environment. A logged user is required: main.inc.php shows the login form first if needed
// and comes back to this URL with its query string.
require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverauthcode.class.php';

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(['oauthserver']);

if (!isModEnabled('oauthserver')) {
	accessforbidden();
}

// The code travels in the redirect: HTTPS is required (OAUTHSERVER_ALLOW_HTTP lifts it on development instances)
if (!oauthserverIsSecureRequest()) {
	http_response_code(400);
	llxHeader('', $langs->trans("OAuthAuthorizationRequest"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-authorize');
	print info_admin($langs->trans("OAuthErrorHttpsRequired"), 0, 0, 'error');
	llxFooter();
	$db->close();
	exit;
}

$action = GETPOST('action', 'aZ09', 0, null, null, 1, 1);
$response_type = GETPOST('response_type', 'aZ09', 0, null, null, 1, 1);
$client_id = GETPOST('client_id', 'aZ09', 0, null, null, 1, 1);
$redirect_uri = GETPOST('redirect_uri', 'alphanohtml', 0, null, null, 1, 1);
$scope = GETPOST('scope', 'alphanohtml', 0, null, null, 1, 1);
$state = GETPOST('state', 'alphanohtml', 0, null, null, 1, 1);
$code_challenge = GETPOST('code_challenge', 'aZ09', 0, null, null, 1, 1);
$code_challenge_method = GETPOST('code_challenge_method', 'aZ09', 0, null, null, 1, 1);
$resource = GETPOST('resource', 'alphanohtml', 0, null, null, 1, 1);

$permissiontoauthorize = ($user->id > 0);  // any logged user may grant access to his own account
$issuer = oauthserverGetIssuer();


/*
 * Actions
 */

// Client and redirect URI first: when they are wrong, never redirect (RFC 6749 section 4.1.2.1)
$client = new OAuthServerClient($db);
$clientok = ($client_id !== '' && $client->fetch(0, $client_id) > 0 && (int) $client->status === OAuthServerClient::STATUS_ENABLED
	&& (int) $client->entity === (int) $conf->entity && $client->hasRedirectUri($redirect_uri));
if (!$clientok) {
	http_response_code(400);
	llxHeader('', $langs->trans("OAuthAuthorizationRequest"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-authorize');
	print info_admin($langs->trans("OAuthErrorUnknownClientOrRedirectUri"), 0, 0, 'error');
	llxFooter();
	$db->close();
	exit;
}

// Other errors are reported to the client through its redirect URI
$errorcode = '';
$scopes = null;
if ($response_type !== 'code') {
	$errorcode = 'unsupported_response_type';
} elseif ($code_challenge_method !== 'S256' || !preg_match('/^[A-Za-z0-9_-]{43,128}$/', $code_challenge)) {
	$errorcode = 'invalid_request';
} else {
	$scopes = oauthserverResolveScopes($scope, $client->allowed_scopes, $resource, $errorcode);
}
if ($scopes === null) {
	$errorcode = ($errorcode !== '' ? $errorcode : 'invalid_request');
	if ($client->registration_type === 'dynamic') {
		// Anybody can register a client with any redirect URI: an error redirect before the user
		// consented would make this server an open redirector (RFC 9700 section 4.11.2)
		http_response_code(400);
		llxHeader('', $langs->trans("OAuthAuthorizationRequest"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-authorize');
		print info_admin($langs->trans("OAuthErrorInvalidAuthorizationRequest", $errorcode), 0, 0, 'error');
		llxFooter();
		$db->close();
		exit;
	}
	header('Location: '.oauthserverBuildRedirectUrl($redirect_uri, ['error' => $errorcode, 'state' => $state, 'iss' => $issuer]));
	exit;
}

if ($action == 'deny' && $permissiontoauthorize) {
	header('Location: '.oauthserverBuildRedirectUrl($redirect_uri, ['error' => 'access_denied', 'state' => $state, 'iss' => $issuer]));
	exit;
}

if ($action == 'allow' && $permissiontoauthorize && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$authcode = new OAuthServerAuthCode($db);
	$authcode->entity = (int) $conf->entity;
	$authcode->fk_oauth_client = (int) $client->id;
	$authcode->fk_user = (int) $user->id;
	$authcode->redirect_uri = $redirect_uri;
	$authcode->scopes = $scopes;
	$authcode->resource = $resource;
	$authcode->code_challenge = $code_challenge;
	$authcode->code_challenge_method = 'S256';
	$code = $authcode->create();
	if ($code === '') {
		dol_syslog('oauthserver authorize: the code could not be stored: '.$authcode->error, LOG_ERR);
		header('Location: '.oauthserverBuildRedirectUrl($redirect_uri, ['error' => 'server_error', 'state' => $state, 'iss' => $issuer]));
		exit;
	}
	header('Location: '.oauthserverBuildRedirectUrl($redirect_uri, ['code' => $code, 'state' => $state, 'iss' => $issuer]));
	exit;
}


/*
 * View
 */

llxHeader('', $langs->trans("OAuthAuthorizationRequest"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-authorize');

print load_fiche_titre($langs->trans("OAuthAuthorizationRequest"), '', 'technic');

print '<div class="center">';
print '<p class="large">'.dol_escape_htmltag($langs->transnoentitiesnoconv("OAuthConsentIntro", $client->label, $user->login)).'</p>';
if ($client->registration_type === 'dynamic') {
	print info_admin($langs->trans("OAuthClientNotVerified"), 0, 0, 'warning');
}
print '<p>'.dol_escape_htmltag($langs->transnoentitiesnoconv("OAuthConsentRedirectHost", (string) parse_url($redirect_uri, PHP_URL_HOST))).'</p>';
print '</div>';

print '<div class="center"><ul class="inline-block left">';
foreach ($scopes as $grantedscope) {
	print '<li>'.dol_escape_htmltag($langs->transnoentitiesnoconv('OAuthScopeDesc_'.$grantedscope)).'</li>';
}
print '</ul></div>';

print '<form method="POST" action="'.dol_escape_htmltag($_SERVER["PHP_SELF"]).'" class="center">';
print '<input type="hidden" name="token" value="'.newToken().'">';
foreach (['response_type' => $response_type, 'client_id' => $client_id, 'redirect_uri' => $redirect_uri, 'scope' => $scope, 'state' => $state,
	'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method, 'resource' => $resource] as $key => $value) {
	print '<input type="hidden" name="'.$key.'" value="'.dolPrintHTMLForAttribute($value).'">';
}
print '<button type="submit" name="action" value="allow" class="button button-save">'.$langs->trans("OAuthAllow").'</button> ';
print '<button type="submit" name="action" value="deny" class="button button-cancel">'.$langs->trans("OAuthDeny").'</button>';
print '</form>';

llxFooter();
$db->close();
