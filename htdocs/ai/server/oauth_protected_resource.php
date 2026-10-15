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
 * \file    htdocs/ai/server/oauth_protected_resource.php
 * \ingroup ai
 * \brief   OAuth Protected Resource Metadata (RFC 9728) of the MCP server, when the module OAuth Server is enabled
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

require '../../main.inc.php';

if (!isModEnabled('ai') || !getDolGlobalString('AI_MCP_ENABLED') || !isModEnabled('oauthserver')) {
	http_response_code(404);
	exit;
}

require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';

// Same rule as the metadata of the authorization server: an http:// URL is never advertised
if (!oauthserverIsSecureRequest()) {
	oauthserverSendError(400, 'invalid_request', 'HTTPS is required');
	exit;
}

oauthserverSendJson(200, [
	'resource' => oauthserverGetResourceUrl('mcp'),
	'authorization_servers' => [oauthserverGetIssuer()],
	'scopes_supported' => ['mcp', 'read', 'write', 'offline_access'],
	'bearer_methods_supported' => ['header'],
], ['Access-Control-Allow-Origin: *']);
