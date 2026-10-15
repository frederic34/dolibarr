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
 * \file    htdocs/oauthserver/admin/setup.php
 * \ingroup oauthserver
 * \brief   Setup page of the module OAuth Server
 */

// Load Dolibarr environment
require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/geturl.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formsetup.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var HookManager $hookmanager
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(['admin', 'oauthserver']);

if (!$user->admin || !isModEnabled('oauthserver')) {
	accessforbidden();
}

$action = GETPOST('action', 'aZ09');
$modulepart = GETPOST('modulepart', 'aZ09');	// Used by actions_setmoduleoptions.inc.php

$formSetup = new FormSetup($db);
$item = $formSetup->newItem('OAUTHSERVER_ACCESS_TOKEN_LIFETIME');
$item->setAsNumber(60, 86400);
$item->fieldParams['isMandatory'] = 1;
$item = $formSetup->newItem('OAUTHSERVER_REFRESH_TOKEN_LIFETIME');
$item->setAsNumber(3600, 31536000);
$item->fieldParams['isMandatory'] = 1;

$setupnotempty = count($formSetup->items);
$permissiontotestdiscovery = $user->admin;


/*
 * Actions
 */

include DOL_DOCUMENT_ROOT.'/core/actions_setmoduleoptions.inc.php';

$discoveryresult = '';
if ($action == 'testdiscovery' && $permissiontotestdiscovery) {
	$result = getURLContent(oauthserverGetWellKnownUrl(), 'GET', '', 0, [], ['https', 'http'], 2);
	$json = (empty($result['content']) ? null : json_decode((string) $result['content'], true));
	if ((int) $result['http_code'] === 200 && is_array($json) && ($json['issuer'] ?? '') === oauthserverGetIssuer()) {
		$discoveryresult = 'ok';
	} else {
		$discoveryresult = 'ko';
	}
}


/*
 * View
 */

$title = $langs->trans("OAuthServerSetup");
llxHeader('', $title, '', '', 0, 0, '', '', '', 'mod-oauthserver page-admin_setup');

$linkback = '<a href="'.DOL_URL_ROOT.'/admin/modules.php?restore_lastsearch_values=1">'.img_picto($langs->trans("BackToModuleList"), 'back', 'class="pictofixedwidth"').'<span class="hideonsmartphone">'.$langs->trans("BackToModuleList").'</span></a>';
print load_fiche_titre($title, $linkback, 'title_setup');

$head = oauthserverAdminPrepareHead();
print dol_get_fiche_head($head, 'settings', $title, -1, 'technic');

if (strpos(DOL_MAIN_URL_ROOT, 'https://') !== 0) {
	print info_admin($langs->trans("OAuthServerHttpsRequired"), 0, 0, 'warning');
}

print '<span class="opacitymedium">'.$langs->trans("OAuthServerSetupDesc").'</span><br><br>';

if ($action == 'edit') {
	print $formSetup->generateOutput(true);
} else {
	print $formSetup->generateOutput();
	print '<div class="tabsAction"><a class="butAction" href="'.$_SERVER["PHP_SELF"].'?action=edit&token='.newToken().'">'.$langs->trans("Modify").'</a></div>';
}

// URLs to give to the clients
print load_fiche_titre($langs->trans("OAuthServerUrls"), '', '');
print '<table class="noborder centpercent">';
print '<tr class="liste_titre"><td>'.$langs->trans("Parameter").'</td><td>'.$langs->trans("Value").'</td></tr>';
$urls = [
	'OAuthIssuer' => oauthserverGetIssuer(),
	'OAuthMetadataUrl' => oauthserverGetIssuer().'/metadata.php',
	'OAuthWellKnownUrl' => oauthserverGetWellKnownUrl(),
	'OAuthApiResourceUrl' => oauthserverGetResourceUrl('api'),
];
foreach ($urls as $key => $url) {
	print '<tr class="oddeven"><td>'.$langs->trans($key).'</td><td>'.showValueWithClipboardCPButton($url, 0).'</td></tr>';
}
print '</table><br>';

// Discovery self-test and web server rules
print load_fiche_titre($langs->trans("OAuthDiscovery"), '', '');
print '<span class="opacitymedium">'.$langs->trans("OAuthDiscoveryDesc").'</span><br><br>';
if ($discoveryresult === 'ok') {
	print info_admin($langs->trans("OAuthDiscoveryOk"), 0, 0, 'info');
} elseif ($discoveryresult === 'ko') {
	print info_admin($langs->trans("OAuthDiscoveryKo", oauthserverGetWellKnownUrl()), 0, 0, 'warning');
}
$rules = oauthserverGetRewriteRules();
print '<div class="div-table-responsive-no-min"><table class="noborder centpercent">';
print '<tr class="liste_titre"><td>Apache</td><td>Nginx</td></tr>';
print '<tr class="oddeven"><td><pre>'.dol_escape_htmltag($rules['apache'], 0, 1).'</pre></td><td><pre>'.dol_escape_htmltag($rules['nginx'], 0, 1).'</pre></td></tr>';
print '</table></div>';
print '<div class="tabsAction"><a class="butAction" href="'.$_SERVER["PHP_SELF"].'?action=testdiscovery&token='.newToken().'">'.$langs->trans("OAuthDiscoveryTest").'</a></div>';

print dol_get_fiche_end();

llxFooter();
$db->close();
